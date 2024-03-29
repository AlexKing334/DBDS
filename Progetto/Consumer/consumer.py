import os
import ssl
import json
import hmac
import time
import base64
import psutil
import hashlib
import logging
import requests
from OpenSSL import crypto
from threading import Thread
from flask import Flask, jsonify
from datetime import timedelta, datetime, timezone
from urllib3.exceptions import InsecureRequestWarning
from confluent_kafka import Consumer, TopicPartition, OFFSET_END, KafkaException


def genera_token(data_to_send):
    data = {'username': 'consumer', 'json': data_to_send, 'create': datetime.utcnow().isoformat(), 'exp': (datetime.utcnow() + timedelta(seconds=30)).isoformat()}
    dati_json = json.dumps(data)
    firma_hmac = hmac.new(chiave_segreta_2.encode('utf-8'), dati_json.encode('utf-8'), hashlib.sha256).digest()
    firma_base64 = base64.b64encode(firma_hmac).decode('utf-8')
    token = f"{dati_json}|{firma_base64}"
    return token


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


def send_data(data_to_send):
    try:
        with app.app_context():
            url = "https://notifier:4000/notify"
            payload = {'token': genera_token(data_to_send)}
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            response = requests.post(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
            result = response.json()
            if result['success']:
                return jsonify({'success': True, 'message': 'Accesso riuscito!'})
            else:
                return jsonify({'success': False, 'message': result['message']})
    except Exception as err:
        logger.info(err)


def LaunchServerThread():
    new_thread = Thread(target=ServerThread)
    new_thread.start()


def ServerThread():
    with app.app_context():
        try:
            @app.route('/send_performance', methods=['GET'])
            def send_performance():
                ram, cpu = memory_usage()
                return jsonify({'success': True, 'ram': ram, 'cpu': cpu})

            generate_self_signed_cert(ssl_cert, ssl_key)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.verify_mode = ssl.CERT_NONE
            context.load_cert_chain(ssl_cert, keyfile=ssl_key)
            app.run(host=HOST, port=PORT, debug=True, use_reloader=False, ssl_context=context)
        except Exception as e:
            logger.info("Errore generico nel thread_server: %s", e)
        finally:
            if not app:
                LaunchServerThread()


def error_consumer():
    logger.info("Errore, Broker Kafka non raggiungibile! Riconnessione in corso")
    time.sleep(15)
    consumer_()


def consumer_():
    logger.info("Broker Kafka raggiunto")
    consumer = None
    try:
        LaunchServerThread()
        consumer_conf = {'bootstrap.servers': 'kafka:9092', 'group.id': 'my-consumer-group', 'auto.offset.reset': 'latest'}
        datetime.now(timezone.utc)
        consumer = Consumer(consumer_conf)
        current = datetime.now(timezone.utc)
        topics = {'SICILIA': current, 'LAZIO': current}
        topics_ = list(topics.keys())
        consumer.subscribe(topics_)
        timeout_ms = 1000
        while True:
            for topic, last_timestamp in topics.items():
                tp = TopicPartition(topic, 0, OFFSET_END)
                last_offset = consumer.get_watermark_offsets(tp)[1]
                start_offset = max(0, last_offset - 1)
                tp.offset = start_offset
                consumer.assign([tp])
                msg = consumer.poll(timeout_ms)
                if msg is not None and not msg.error():
                    data_to_send = []
                    json_data = json.loads(msg.value().decode('utf-8'))
                    for city_info in json_data:
                        location = city_info['location']
                        temperature = city_info['temperature']
                        humidity = city_info['humidity']
                        precipitation_probability = city_info['precipitation_probability']
                        timestamp = datetime.strptime(city_info['timestamp'], "%Y-%m-%dT%H:%M:%S.000%z")
                        current_time = datetime.now(timezone.utc) - timedelta(hours=1)
                        time_difference = current_time - timestamp
                        if last_timestamp != timestamp and time_difference.total_seconds() < 75:
                            topics[topic] = timestamp
                            json_data = {"location": location, 'temperature': temperature, 'humidity': humidity,
                                         "precipitation_probability": precipitation_probability}
                            data_to_send.append(json_data)
                    if len(data_to_send) != 0:
                        logger.info("Dati inoltrati al notifier %s", current_time)
                        send_data(data_to_send)

    except KafkaException as e:
        logger.info('KafkaException: %s', e)
    except KeyboardInterrupt:
        logger.info("Consumer interrotto manualmente")
    except Exception as err:
        logger.info(str(err))
    finally:
        consumer.close()
        error_consumer()
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Avvio Consumer in corso...")

    ssl_cert = './cert.pem'
    ssl_key = './privkey.pem'
    generate_self_signed_cert(ssl_cert, ssl_key)
    try:
        HOST = os.environ['HOST']
        PORT = os.environ['PORT']
        chiave_segreta_2 = os.environ['SIGN_KEY_CONSUMER']
    except KeyError as err:
        logger.info("Variabili d'ambiente non impostate correttamente")
        logger.info(err)

    app = Flask(__name__)
    consumer_()
