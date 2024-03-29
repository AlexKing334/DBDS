import os
import ssl
import time
import json
import hmac
import socket
import base64
import docker
import psutil
import hashlib
import logging
import requests
from OpenSSL import crypto
from threading import Thread
from datetime import datetime
import prometheus_client
from flask import Flask, request, jsonify
from urllib3.exceptions import InsecureRequestWarning
from prometheus_client import generate_latest, CollectorRegistry


def verifica_token(token):
    try:
        dati_json, firma_base64 = token.split('|', 1)
        data = json.loads(dati_json)
        exp_datetime = datetime.fromisoformat(data["exp"])
        if datetime.utcnow() > exp_datetime:
            return False
        else:
            firma_calcolata = hmac.new(chiave_segreta.encode('utf-8'), dati_json.encode('utf-8'), hashlib.sha256).digest()
            firma_calcolata_base64 = base64.b64encode(firma_calcolata).decode('utf-8')
            if firma_calcolata_base64 == firma_base64:
                return True
            else:
                return False
    except Exception as e:
        logger.info(e)
        return False


def get_containers():
    client = docker.from_env()
    try:
        running_container = client.containers.list()
        return running_container
    except docker.errors.NotFound:
        logger.info("Container not found.")
        return None
    finally:
        client.close()


def create_metric_container():
    try:
        containers_ = get_containers()
        container_metrics_ = {}
        for container in containers_:
            container_name_for_metric = container.name.replace('-', '_')
            ram_usage = prometheus_client.Gauge(f'{container_name_for_metric}_RAM_USAGE', f'{container_name_for_metric}_RAM_USAGE', ['server'])
            cpu_usage = prometheus_client.Gauge(f'{container_name_for_metric}_CPU_USAGE', f'{container_name_for_metric}_CPU_USAGE', ['server'])
            container_metrics_[container.name] = {
                'RAM_USAGE': ram_usage,
                'CPU_USAGE': cpu_usage
            }
        return container_metrics_, containers_
    except Exception as err:
        logger.info(err)


def generate_self_signed_cert(cert_file, key_, days_valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "Consumer"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(days_valid * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        with open(cert_file, 'wb') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_, 'wb') as key_:
            key_.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    except Exception as err:
        logger.info(err)


def memory_usage():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cpu_info = psutil.cpu_percent(interval=1, percpu=False)
    return mem_info.rss, cpu_info


def request_Performance(url, ram_metric, cpu_metric):
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, cert=(ssl_cert, ssl_key), verify=False)
        result = response.json()
        if result['success']:
            ram = result['ram'] / (1024 * 1024)
            logger.info("name: %s CPU: %s RAM: %s", url, result['cpu'], ram)
            ram_metric.labels(server='localhost').set(ram)
            cpu_metric.labels(server='localhost').set(result['cpu'])
        else:
            logger.info("Errore nel contattare il server %s", url)
    except Exception:
        logger.info("Errore nel contattare il server %s", url)


def request_online_user(url, metric):
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, cert=(ssl_cert, ssl_key), verify=False)
        result = response.json()
        if result['success']:
            online_user = result['online_user']
            logger.info("online user: %s ", online_user)
            metric.labels(server='localhost').set(online_user)
        else:
            logger.info("Errore nel contattare il server %s", url)
    except Exception:
        logger.info("Errore nel contattare il server %s", url)


def check_day_change():
    current_date = datetime.now().date()
    while True:
        time.sleep(1)
        new_date = datetime.now().date()
        if new_date > current_date:
            current_date = new_date
            logger.info("it's a new day for the exporter!", current_date)
            ResetMetric()


def ResetMetric():
    NOTIFIER_DAILY_COUNT.labels(server='localhost').set(0)
    return generate_latest()


def new_day_change_thread():
    new_day_change_threa = Thread(target=check_day_change)
    new_day_change_threa.start()


def update_performance():
    try:
        while True:
            time.sleep(30)
            for container_ in containers:
                metrics = container_metrics[container_.name]
                monitor_container_stats(container_, metrics['RAM_USAGE'], metrics['CPU_USAGE'])
            request_Performance("https://notifier:4000/send_performance", RAM_NOTIFIER_USAGE, CPU_NOTIFIER_USAGE)
            request_Performance("https://producer:1000/send_performance", RAM_PRODUCER_USAGE, CPU_PRODUCER_USAGE)
            request_Performance("https://usermanager:5000/send_performance", RAM_SERVER_USAGE, CPU_SERVER_USAGE)
            request_Performance("https://subscriber:8001/send_performance", RAM_SUBSCRIBER_USAGE, CPU_SUBSCRIBER_USAGE)
            request_Performance("https://consumer:6000/send_performance", RAM_CONSUMER_USAGE, CPU_CONSUMER_USAGE)
            request_Performance("https://slamanager:7000/send_performance", RAM_SLA_USAGE, CPU_SLA_USAGE)
            request_Performance("https://sarima:5555/send_performance", RAM_SARIMA_USAGE, CPU_SARIMA_USAGE)
            request_online_user("https://usermanager:5000/online_user", SERVER_USER_ONLINE)
    except requests.exceptions.ConnectionError:
        logger.info(f"Errore di connessione al server")
    except requests.exceptions.RequestException:
        logger.info(f"Errore durante la richiesta al server")
    except Exception:
        logger.info("Errore generico durante l'update delle performance")
    finally:
        update_performance_thread()


def update_performance_thread():
    new_performance_thread = Thread(target=update_performance)
    new_performance_thread.start()


def monitor_container_stats(container_, ram_metric, cpu_metric):
    client = docker.from_env()
    try:
        for stat in container_.stats(decode=True):
            cpu_stats = stat.get('cpu_stats', {})
            precpu_stats = stat.get('precpu_stats', {})
            cpu_delta = cpu_stats.get('cpu_usage', {}).get('total_usage', 0) - precpu_stats.get('cpu_usage', {}).get('total_usage', 0)
            system_delta = cpu_stats.get('system_cpu_usage', 0) - precpu_stats.get('system_cpu_usage', 0)
            number_of_cores = len(cpu_stats.get('cpu_usage', {}).get('percpu_usage', []))
            try:
                cpu_percent = (cpu_delta / system_delta) * number_of_cores * 100
            except ZeroDivisionError:
                cpu_percent = 0.0
            mem_usage = stat.get('memory_stats', {}).get('usage', 0) / (1024 * 1024)
            logger.info("name: %s CPU: %s RAM: %s", container_.name, cpu_percent, mem_usage)
            ram_metric.labels(server='localhost').set(mem_usage)
            cpu_metric.labels(server='localhost').set(cpu_percent)
            break
    except docker.errors.NotFound as e:
        logger.info(f"Container not found: {e}")
    except Exception as e:
        logger.info(f"Error during container monitoring: {e}")
    finally:
        client.close()


app = Flask(__name__)


def is_k8s():
    return 'KUBERNETES_SERVICE_HOST' in os.environ


@app.route('/metrics', methods=['GET'])
def metric():
    flag = False
    request_ip = request.remote_addr
    if is_k8s():
        flag = True
    else:
        try:
            ip_prometheus = socket.gethostbyname('prometheus')
            logger.info("prometheus docker: %s ", ip_prometheus)
            if str(request_ip) == str(ip_prometheus):
                flag = True
        except Exception:
            logger.info("Errore durante l'ottenimento dell'ip Prometheus")

    if flag:
        mem_info, cpu_info = memory_usage()
        RAM_EXPORTER_USAGE.labels(server='localhost').set(mem_info/(1024*1024))
        CPU_EXPORTER_USAGE.labels(server='localhost').set(cpu_info)
        return generate_latest()
    else:
        logger.info("Metrics: Accesso negato all'indirizzo %s", request_ip)
        return "Accesso negato", 403


@app.route('/metrics/SLA', methods=['GET'])
def metrics_SLA():
    data = request.get_json()
    if verifica_token(data['token']):
        mem_info, cpu_info = memory_usage()
        RAM_EXPORTER_USAGE.labels(server='localhost').set(mem_info/(1024*1024))
        CPU_EXPORTER_USAGE.labels(server='localhost').set(cpu_info)
        custom_registry = CollectorRegistry()
        custom_registry.register(RAM_EXPORTER_USAGE)
        custom_registry.register(CPU_EXPORTER_USAGE)
        custom_registry.register(RAM_CONSUMER_USAGE)
        custom_registry.register(CPU_CONSUMER_USAGE)
        custom_registry.register(RAM_PRODUCER_USAGE)
        custom_registry.register(CPU_PRODUCER_USAGE)
        custom_registry.register(RAM_NOTIFIER_USAGE)
        custom_registry.register(CPU_NOTIFIER_USAGE)
        custom_registry.register(RAM_SUBSCRIBER_USAGE)
        custom_registry.register(CPU_SUBSCRIBER_USAGE)
        custom_registry.register(RAM_SLA_USAGE)
        custom_registry.register(CPU_SLA_USAGE)
        custom_registry.register(RAM_SERVER_USAGE)
        custom_registry.register(CPU_SERVER_USAGE)
        custom_registry.register(RAM_SARIMA_USAGE)
        custom_registry.register(CPU_SARIMA_USAGE)
        return generate_latest(registry=custom_registry)
    else:
        logger.info("tentativo di richiesta POST con token invalido")


@app.route('/notifier', methods=['POST'])
def notifier_data():
    try:
        data = request.get_json()
        NOTIFIER_TOTAL_COUNT.labels(server='localhost').inc(data['count'])
        NOTIFIER_DAILY_COUNT.labels(server='localhost').inc(data['count'])
        return jsonify({'success': True})
    except Exception as e:
        logger.info(e)
        return jsonify({'success': False})


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    try:
        chiave_segreta = os.environ.get('SIGN_KEY_EXPORTER')
        PORT = os.environ['PORT']
        HOST = os.environ['HOST']
    except KeyError as err:
        logger.info("Variabili d'ambiente non impostate correttamente")
        logger.info(err)

    ssl_cert = './cert.pem'
    ssl_key = './privkey.pem'
    generate_self_signed_cert(ssl_cert, ssl_key)

    try:
        container_metrics, containers = create_metric_container()
    except Exception:
        logger.info("Errore durante la creazione dei container-Docker")
        containers = []
        container_metrics = []

    RAM_EXPORTER_USAGE = prometheus_client.Gauge('RAM_EXPORTER_USAGE', 'RAM_EXPORTER_USAGE', ['server'])
    CPU_EXPORTER_USAGE = prometheus_client.Gauge('CPU_EXPORTER_USAGE', 'CPU_EXPORTER_USAGE', ['server'])
    RAM_PRODUCER_USAGE = prometheus_client.Gauge('RAM_PRODUCER_USAGE', 'RAM_PRODUCER_USAGE', ['server'])
    CPU_PRODUCER_USAGE = prometheus_client.Gauge('CPU_PRODUCER_USAGE', 'CPU_PRODUCER_USAGE', ['server'])
    RAM_NOTIFIER_USAGE = prometheus_client.Gauge('RAM_NOTIFIER_USAGE', 'RAM_NOTIFIER_USAGE', ['server'])
    CPU_NOTIFIER_USAGE = prometheus_client.Gauge('CPU_NOTIFIER_USAGE', 'CPU_NOTIFIER_USAGE', ['server'])
    RAM_SERVER_USAGE = prometheus_client.Gauge('RAM_SERVER_USAGE', 'RAM_SERVER_USAGE', ['server'])
    CPU_SERVER_USAGE = prometheus_client.Gauge('CPU_SERVER_USAGE', 'CPU_SERVER_USAGE', ['server'])
    RAM_SUBSCRIBER_USAGE = prometheus_client.Gauge('RAM_SUBSCRIBER_USAGE', 'RAM_SUBSCRIBER_USAGE', ['server'])
    CPU_SUBSCRIBER_USAGE = prometheus_client.Gauge('CPU_SUBSCRIBER_USAGE', 'CPU_SUBSCRIBER_USAGE', ['server'])
    RAM_CONSUMER_USAGE = prometheus_client.Gauge('RAM_CONSUMER_USAGE', 'RAM_CONSUMER_USAGE', ['server'])
    CPU_CONSUMER_USAGE = prometheus_client.Gauge('CPU_CONSUMER_USAGE', 'CPU_CONSUMER_USAGE', ['server'])
    RAM_SLA_USAGE = prometheus_client.Gauge('RAM_SLA_USAGE', 'RAM_SLA_USAGE', ['server'])
    CPU_SLA_USAGE = prometheus_client.Gauge('CPU_SLA_USAGE', 'CPU_SLA_USAGE', ['server'])
    RAM_SARIMA_USAGE = prometheus_client.Gauge('RAM_SARIMA_USAGE', 'RAM_SARIMA_USAGE', ['server'])
    CPU_SARIMA_USAGE = prometheus_client.Gauge('CPU_SARIMA_USAGE', 'CPU_SARIMA_USAGE', ['server'])
    NOTIFIER_TOTAL_COUNT = prometheus_client.Counter('NOTIFIER_TOTAL_COUNT', 'NOTIFIER_TOTAL_COUNT', ['server'])
    NOTIFIER_DAILY_COUNT = prometheus_client.Gauge('NOTIFIER_DAILY_COUNT', 'NOTIFIER_DAILY_COUNT', ['server'])
    SERVER_USER_ONLINE = prometheus_client.Gauge('SERVER_USER_ONLINE', 'SERVER_USER_ONLINE', ['server'])

    new_day_change_thread()
    update_performance_thread()
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    app.run(host=HOST, port=PORT, debug=True, use_reloader=False, ssl_context=context)
