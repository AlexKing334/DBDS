import os
import ssl
import json
import time
import psutil
import logging
from OpenSSL import crypto
from threading import Thread
from datetime import datetime
import meteomatics.api as api
from flask import Flask, jsonify
from confluent_kafka import Producer


def generate_self_signed_cert(cert_file, key_, days_valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "Producer"
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


def delivery_report(err, msg):
    if err is not None:
        logger.info(f'Errore in consegna: {err}')
    else:
        logger.info(f'Messaggio consegnato a {msg.topic()} [{msg.partition()}] @ offset {msg.offset()}')


def LaunchServerThread():
    new_thread = Thread(target=ServerThread)
    new_thread.start()


def ServerThread():
    app = Flask(__name__)
    try:
        @app.route('/send_performance', methods=['GET'])
        def send_performance():
            ram, cpu = memory_usage()
            return jsonify({'success': True, 'ram': ram, 'cpu': cpu})
    
        ssl_cert = './cert.pem'
        ssl_key = './privkey.pem'
        generate_self_signed_cert(ssl_cert, ssl_key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(ssl_cert, keyfile=ssl_key)
        app.run(host=HOST, port=PORT, debug=True, use_reloader=False, ssl_context=context)
    except Exception:
        logger.info("Errore generico nel thread_Server")
    finally:
        LaunchServerThread()


def producer():
    try:
        producer_conf = {'bootstrap.servers': 'kafka:9092'}
        producer = Producer(producer_conf)
        while True:
            time.sleep(60)
            now = datetime.now()
            timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.000+01:00")
            sicily = f"https://api.meteomatics.com/{timestamp}/t_2m:C,prob_precip_24h:p,relative_humidity_2m:p/" \
                     f"37.5023612,15.0873718+37.0646139,15.2907196+38.1112268,13.3524434+37.5854195," \
                     f"14.488893+38.0174321,12.515992+38.1937571,15.5542082+36.9219828,14.7213455+37.3122991," \
                     f"13.57465+37.4899412,14.0631618/json?model=mix"
            lazio = f"https://api.meteomatics.com/{timestamp}/t_2m:C,prob_precip_24h:p,relative_humidity_2m:p/" \
                    f"41.8933203,12.4829321+42.4929522,11.9488136+41.6285468,13.5758498+41.4595261,13.0125912+42.4147363,12.8858881/json?model=mix"

            maps = {
                'SICILIA': (sicily, {"Catania": 0, "Siracusa": 1, "Palermo": 2, "Enna": 3, "Trapani": 4, "Messina": 5, "Ragusa": 6, "Agrigento": 7, "Caltanissetta": 8}),
                'LAZIO': (lazio, {"Roma": 0, "Viterbo": 1, "Frosinone": 2, "Latina": 3, "Rieti": 4}),
            }
            for name, values in maps.items():
                url, cities = values
                response = api.query_api(url, USER, PSW)
                if response.status_code == 200:
                    data = response.json()
                    city_list = []
                    for city, position in cities.items():
                        temperature = data['data'][0]['coordinates'][position]['dates'][0]['value']
                        precipitation_probability = data['data'][1]['coordinates'][position]['dates'][0]['value']
                        humidity = data['data'][2]['coordinates'][position]['dates'][0]['value']
                        json_data = {"location": city, 'temperature': temperature, 'humidity': humidity,
                                     "precipitation_probability": precipitation_probability, "timestamp": timestamp}
                        city_list.append(json_data)
                    to_kafka = json.dumps(city_list)
                    producer.produce(name, key=None, value=to_kafka, partition=0, callback=delivery_report)
                    producer.flush()
                else:
                    logger.info("Request failed with status code %s", response.status_code)
    except KeyboardInterrupt:
        logger.info("Producer interrotto manualmente")
    except Exception as err:
        logger.info("Errore %s", err)
    finally:
        Producer()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Avvio Producer in corso...")

    try:
        HOST = os.environ['HOST']
        PORT = os.environ['PORT']
        USER = os.environ['USER']
        PSW = os.environ['PSW']
    except KeyError:
        logger.info("Le variabili di ambiente non sono state impostate correttamente!")
    LaunchServerThread()
    producer()
