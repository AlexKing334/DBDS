import os
import ssl
import time
import hmac
import json
import base64
import psutil
import hashlib
import logging
import requests
import mysql.connector
from OpenSSL import crypto
import circuitbreaker as cb
from threading import Thread
from requests import RequestException
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from urllib3.exceptions import InsecureRequestWarning
from tenacity import retry, stop_after_attempt, wait_fixed
from prometheus_client.parser import text_string_to_metric_families

cb_db = cb.CircuitBreaker("db")
app = Flask(__name__)


def genera_token():
    data = {'username': 'slamanager', 'create': datetime.utcnow().isoformat(), 'exp': (datetime.utcnow() + timedelta(seconds=60)).isoformat()}
    dati_json = json.dumps(data)
    firma_hmac = hmac.new(chiave_segreta_2.encode('utf-8'), dati_json.encode('utf-8'), hashlib.sha256).digest()
    firma_base64 = base64.b64encode(firma_hmac).decode('utf-8')
    token = f"{dati_json}|{firma_base64}"
    return token


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def get_sla_list():
    conn = mysql.connector.connect(host='db-sla', user='root', password='', database='DBDS3')
    cursor = conn.cursor(dictionary=True)
    query = "SELECT  id, name , threshold, isActive FROM sla_rules"
    cursor.execute(query)
    threshold_lista = cursor.fetchall()
    cursor.close()
    conn.close()
    if threshold_lista:
        return True, threshold_lista
    else:
        return True, None


def get_violation_list(type_req, value):
    conn = mysql.connector.connect(host='db-sla', user='root', password='', database='DBDS3')
    cursor = conn.cursor(dictionary=True)
    query = None
    if type_req == "hours":
        query = f"SELECT id, name, value, timestamp FROM historical_sla_violation " \
                f"WHERE TIMESTAMPDIFF(HOUR, historical_sla_violation.timestamp, NOW()) <= {value}"
    if type_req == "days":
        query = f"SELECT id, name, value, timestamp FROM historical_sla_violation " \
                f"WHERE TIMESTAMPDIFF(DAY, historical_sla_violation.timestamp, NOW()) <= {value}"
    if type_req == "fromDataToCurrent":
        from_ = datetime.strptime(value, '%Y-%m-%d')
        from_ = from_.replace(hour=0, minute=0, second=1)
        query = f"SELECT id, name, value, timestamp FROM historical_sla_violation " \
                f"WHERE timestamp BETWEEN '{from_}' AND NOW()"
    if type_req == "fromDataToData":
        from_ = datetime.strptime(value['from'], '%Y-%m-%d')
        from_ = from_.replace(hour=0, minute=0, second=1)
        to_ = datetime.strptime(value['to'], '%Y-%m-%d')
        to_ = to_.replace(hour=23, minute=59, second=59)
        query = f"SELECT id, name, value, timestamp FROM historical_sla_violation " \
                f"WHERE timestamp BETWEEN '{from_}' AND '{to_}'"
    cursor.execute(query)
    threshold_lista = cursor.fetchall()
    cursor.close()
    conn.close()
    if threshold_lista:
        return True, threshold_lista
    else:
        return True, None


def generate_self_signed_cert(cert_file, key_, days_valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "Sla_manager"
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
    except Exception as e:
        logger.info("Errore generico durante la generazione del certificato: %s", e)


def update_performance_thread():
    while True:
        try:
            new_performance_thread = Thread(target=update_performance)
            new_performance_thread.start()
            time.sleep(60)
        except Exception:
            logger.info("Errore generico nel thread di update")
        finally:
            update_performance_thread()


def parse_prometheus_response(response_content):
    metrics = {}
    for family in text_string_to_metric_families(response_content):
        for sample in family.samples:
            metric_name = sample.name
            metric_value = sample.value
            metrics[metric_name] = metric_value
    return metrics


@retry(stop=stop_after_attempt(1), after=cb_db.callback_open_circuit_breaker)
def insert_violation(name, value):
    conn = mysql.connector.connect(host='db-sla', user='root', password='', database='DBDS3')
    cursor = conn.cursor()
    query = "INSERT INTO historical_sla_violation (name, value) VALUES (%s, %s)"
    cursor.execute(query, (name, value,))
    conn.commit()
    cursor.close()
    conn.close()
    return True


def is_user_online(token):
    try:
        url = "https://usermanager:5000/is_token_valid"
        payload = {'token': token}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
        result = response.json()
        return result['success']
    except Exception as err:
        logger.info(err)


def verifica_token(token):
    try:
        dati_json, firma_base64 = token.split('|', 1)
        data = json.loads(dati_json)
        exp_datetime = datetime.fromisoformat(data["exp"])
        if not is_user_online(token):
            logger.info("Token revocato %s", token)
            return False, "Errore, utilizzato un Token revocato"
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


def update_performance():
    try:
        url = "https://exporter:2000/metrics/SLA"
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        token = genera_token()
        payload = {'token': token}
        response = requests.get(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
        if response.status_code == 200:
            metrics_data = parse_prometheus_response(response.content.decode('utf-8'))
            _, threshold_list = get_sla_list()
            for metric_name, metric_value in metrics_data.items():
                for threshold in threshold_list:
                    if threshold['name'] == metric_name and threshold["isActive"] and metric_value > float(threshold['threshold']) and not cb_db.is_circuit_breaker_open():
                        insert_violation(metric_name, metric_value)
        else:
            logger.info("Errore nel contattare il server %s", url)
    except RequestException as e:
        logger.info("Errore durante la richiesta  %s", e)


def memory_usage():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cpu_info = psutil.cpu_percent(interval=1, percpu=False)
    return mem_info.rss, cpu_info


@app.route('/send_performance', methods=['GET'])
def send_performance():
    ram, cpu = memory_usage()
    return jsonify({'success': True, 'ram': ram, 'cpu': cpu})


@app.route('/is_token_valid', methods=['GET'])
def is_token_valid():
    data = request.get_json()
    return jsonify({'success': verifica_token(data['token'])})


@app.route('/get_violation', methods=['GET'])
def get_violation():
    try:
        data = request.get_json()
        if verifica_token(data['token']):
            try:
                state, my_list = get_violation_list(data["type_req"], data["value"])
            except Exception as e:
                return jsonify({'success': False, 'message': f'Errore di accesso al db:{str(e)}'})
            if state:
                if my_list is not None:
                    return jsonify({'success': True, 'message': '', 'sla': my_list})
                else:
                    return jsonify({'success': False, 'message': 'empty_list', 'sla': my_list})
            else:
                return jsonify({'success': False, 'message': 'Errore nell\'ottenere l\'elenco delle sottoscrizioni'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/get_sla_rules', methods=['GET'])
def getslarules():
    try:
        data = request.get_json()
        if verifica_token(data['token']):
            try:
                state, my_list = get_sla_list()
            except Exception as e:
                return jsonify({'success': False, 'message': f'Errore di accesso al db:{str(e)}'})
            if state:
                if my_list is not None:
                    return jsonify({'success': True, 'message': '', 'sla': my_list})
                else:
                    return jsonify({'success': False, 'message': 'empty_list', 'sla': my_list})
            else:
                return jsonify({'success': False, 'message': 'Errore nell\'ottenere l\'elenco delle sottoscrizioni'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def update_sla_db(name, threshold, is_active):
    conn = mysql.connector.connect(host='db-sla', user='root', password='', database='DBDS3')
    cursor = conn.cursor()
    query = "UPDATE sla_rules SET threshold = %s, isActive = %s WHERE name = %s"
    cursor.execute(query, (threshold, is_active, name))
    conn.commit()
    cursor.close()
    conn.close()
    return True


@app.route('/update_sla', methods=['PUT'])
def update_sla():
    try:
        data = request.get_json()
        if verifica_token(data['token']):
            name = data['name']
            threshold = data['threshold']
            is_Active = data['isActive']
            if is_Active == "True":
                is_Active = 1
            else:
                is_Active = 0
            try:
                state = update_sla_db(name, threshold, is_Active)
            except Exception as e:
                return jsonify({'success': False, 'message': f'Errore di accesso al db: {str(e)}'})
            if state:
                _, threshold_list = get_sla_list()
                return jsonify({'success': True, 'message': 'SLA modificata con successo'})
            else:
                return jsonify({'success': False, 'message': 'Errore durante la modifica della SLA'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Slamanager in avviamento")
    time.sleep(15)
    logger.info("Slamanager in avviato")
    ssl_cert = './cert.pem'
    ssl_key = './privkey.pem'
    generate_self_signed_cert(ssl_cert, ssl_key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        chiave_segreta = os.environ.get('SIGN_KEY_USERMANAGER_ADMIN')
        chiave_segreta_2 = os.environ.get('SIGN_KEY_EXPORTER')
        PORT = os.environ.get('PORT')
        HOST = os.environ.get('HOST')
    except Exception as e:
        logger.info(e)
    _, threshold_list = get_sla_list()
    new_performance_thread = Thread(target=update_performance_thread)
    new_performance_thread.start()

    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    app.run(host=HOST, port=PORT, debug=True, use_reloader=False, ssl_context=context)
