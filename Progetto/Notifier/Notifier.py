import os
import ssl
import hmac
import json
import psutil
import base64
import smtplib
import logging
import hashlib
import requests
from OpenSSL import crypto
from urllib3.exceptions import InsecureRequestWarning
import circuitbreaker as cb
from threading import Thread
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from tenacity import retry, stop_after_attempt


def genera_token():
    data = {
        'username': "Notifier",
        'create': datetime.utcnow().isoformat(),
        'exp': (datetime.utcnow() + timedelta(minutes=3)).isoformat()
    }
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
        cert.get_subject().CN = "Notifier"
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


def send_data(count):
    try:
        url = "https://exporter:2000/notifier"
        payload = {'count': count}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
        result = response.json()
        if result['success']:
            logger.info("Dati inviati correttamente")
        else:
            logger.info("Errore durante l'invio dei dati")
    except requests.RequestException as req_err:
        logger.error(f"Request error: {req_err}")


cb_mail = cb.CircuitBreaker("mail")


@retry(stop=stop_after_attempt(1), after=cb_mail.callback_open_circuit_breaker)
def invia_email(mail_destinatario, loc, value, req):
    mail_mittente = 'lemongamerz23@gmail.com'
    password = 'nvzwecyfmugneiaq'
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(mail_mittente, password)
    msg = None
    if req == "temperature":
        msg = f"Il tuo vincolo è stato violato: location: {loc} Temperatura registrata: {value}°C"
    if req == "humidity":
        msg = f"Il tuo vincolo è stato violato: location: {loc} Umidità registrata: {value}%"
    if req == "precipitation":
        msg = f"Il tuo vincolo è stato violato: location: {loc} Probabilita di precipitazione registrata: {value}°%"
    msg = MIMEText(msg, 'plain', 'utf-8')
    msg['Subject'] = 'Il tuo vincolo è stato violato'
    server.sendmail(mail_mittente, mail_destinatario, msg.as_string())
    server.quit()


def verifica_token(token):
    logger.info(token)
    try:
        dati_json, firma_base64 = token.split('|', 1)
        firma_calcolata = hmac.new(chiave_segreta.encode('utf-8'), dati_json.encode('utf-8'), hashlib.sha256).digest()
        firma_calcolata_base64 = base64.b64encode(firma_calcolata).decode('utf-8')
        if firma_calcolata_base64 == firma_base64:
            decrypted_data = json.loads(dati_json)
            return True, decrypted_data
        else:
            return False, "Richiesta non autorizzata"
    except Exception as err:
        return False, str(err)


cb_sub = cb.CircuitBreaker("sub")


def memory_usage():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cpu_info = psutil.cpu_percent(interval=1, percpu=False)
    return mem_info.rss, cpu_info


app = Flask(__name__)


@app.route('/send_performance', methods=['GET'])
def send_performance():
    try:
        ram, cpu = memory_usage()
        return jsonify({'success': True, 'ram': ram, 'cpu': cpu})
    except Exception as e:
        return jsonify({'success': False, 'errore': e})


@app.route('/notify', methods=['POST'])
def notify():
    data = request.get_json()
    try:
        state, data_token = verifica_token(data['token'])
        if state:
            json_data = data_token['json']
            response = jsonify({'success': True, 'message': 'Request received. Processing...'})
            process_notifications_async(json_data)
            return response
        else:
            return jsonify({'success': False, 'message': 'Errore, richiesta non autorizzata'})
    except Exception as err:
        logger.info(err)
        return jsonify({'success': False, 'message': "Errore generico nel notifier"})


def process_notifications_async(json_data):
    with app.app_context():
        thread = Thread(target=process_notifications, args=(json_data,))
        thread.start()


@retry(stop=stop_after_attempt(1), after=cb_sub.callback_open_circuit_breaker)
def get_user_list(loc, value, req):
    url = "https://subscriber:8001/get_user_list"
    payload = {'location': loc, 'req': req, 'value': value, 'token': genera_token()}
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response = requests.get(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
    result = response.json()
    if result['success']:
        return True, result['emails']
    else:
        return False, []


@retry(stop=stop_after_attempt(3), after=cb_sub.callback_open_circuit_breaker)
def set_timestamp(user, loc, req):
    url = "https://subscriber:8001/set_timestamp"
    payload = {'location': loc, 'req': req, 'user': user, 'token': genera_token()}
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response = requests.put(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
    result = response.json()
    if result['success']:
        return True
    else:
        return False


def process_notifications(json_data):
    with app.app_context():
        try:
            for el in json_data:
                if not cb_sub.is_circuit_breaker_open():
                    logger.info("Controllo di pre-notificazione avviato")
                    s, user_list = get_user_list(el['location'], el['temperature'], "temperature")
                    s1, user_list_2 = get_user_list(el['location'], el['humidity'], "humidity")
                    s2, user_list_3 = get_user_list(el['location'], el['precipitation_probability'], "precipitation")
                    if s or s1 or s2 or not cb_mail.is_circuit_breaker_open():
                        logger.info("Processo di notificazione avviato")
                        if user_list:
                            logger.info("Processo di notificazione temperatura avviato")
                            for user in user_list:
                                invia_email(user, el['location'], el['temperature'], "temperature")
                                if not cb_sub.is_circuit_breaker_open():
                                    set_timestamp(user, el['location'], "temperature")
                        if user_list_2:
                            logger.info("Processo di notificazione umidita avviato")
                            for user in user_list_2:
                                invia_email(user, el['location'], el['humidity'], "humidity")
                                if not cb_sub.is_circuit_breaker_open():
                                    set_timestamp(user, el['location'], "humidity")
                        if user_list_3:
                            logger.info("Processo di notificazione probabilita precipitazione avviato")
                            for user in user_list_3:
                                invia_email(user, el['location'], el['precipitation_probability'], "precipitation")
                                if not cb_sub.is_circuit_breaker_open():
                                    set_timestamp(user, el['location'], "precipitation")
                    total_mail = int(len(user_list)+len(user_list_2)+len(user_list_3))
                    logger.info("email inviate %s", total_mail)
                    send_data(total_mail)
        except Exception as err:
            logger.info(err)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Avvio Notifier in corso...")

    ssl_cert = './cert.pem'
    ssl_key = './privkey.pem'
    generate_self_signed_cert(ssl_cert, ssl_key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        chiave_segreta = os.environ['SIGN_KEY_CONSUMER']
        chiave_segreta_2 = os.environ['SIGN_KEY_NOTIFIER']
        PORT = os.environ['PORT']
        HOST = os.environ['HOST']
    except KeyError:
        logger.info("La variabile di ambiente non è stata impostata!")

    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    app.run(host=HOST, port=PORT, ssl_context=context)
