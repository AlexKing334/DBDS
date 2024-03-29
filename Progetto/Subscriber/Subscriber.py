import os
import ssl
import hmac
import json
import base64
import psutil
import hashlib
import logging
import requests
import mysql.connector
from OpenSSL import crypto
from datetime import datetime
from flask import Flask, request, jsonify
from urllib3.exceptions import InsecureRequestWarning


def generate_self_signed_cert(cert_file, key_, days_valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "Subscriber"
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
    except Exception:
        logger.info("Errore generico durante la generazione dei certificati")


def memory_usage():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cpu_info = psutil.cpu_percent(interval=1, percpu=False)
    return mem_info.rss, cpu_info


def event_exists(location, user_id):
    try:
        conn = mysql.connector.connect(host='db-sub', user='root', password='', database='DBDS2')
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM condition_notify WHERE location = %s AND email = %s"
        cursor.execute(query, (location, user_id))
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return count > 0
    except mysql.connector.Error:
        logger.info("Errore di connessione DB event_exists")
        return False


def insert_or_update_event(parametri):
    location, t_min, t_max, hum, pre, email = parametri
    try:
        conn = mysql.connector.connect(host='db-sub', user='root', password='', database='DBDS2')
        cursor = conn.cursor()
        cond = event_exists(location, email)
        if cond:
            parametri = (None if not t_min else t_min,
                         None if not t_max else t_max,
                         None if not pre else pre,
                         None if not hum else hum,
                         location,
                         email)
            query = "UPDATE condition_notify SET t_min = %s, t_max = %s, precipitation = %s, humidity = %s WHERE location = %s AND email = %s"
            cursor.execute(query, parametri)
        else:
            parametri = (location,
                         None if not t_min else t_min,
                         None if not t_max else t_max,
                         None if not pre else pre,
                         None if not hum else hum,
                         email)
            query = "INSERT INTO condition_notify (location, t_min, t_max, precipitation, humidity, email) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(query, parametri)
        conn.commit()
        cursor.close()
        conn.close()
        return True, cond

    except mysql.connector.Error:
        logger.info("Errore di connessione DB insert_or_update_event")
        return False, False


def get_user_topic_list(user):
    try:
        conn = mysql.connector.connect(host='db-sub', user='root', password='', database='DBDS2')
        cursor = conn.cursor()
        query = "SELECT location, t_min, t_max, precipitation, humidity FROM condition_notify WHERE email = %s"
        cursor.execute(query, (user,))
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        if results:
            my_list = []
            for result in results:
                data = {
                    'location': result[0],
                    't_min': result[1],
                    't_max': result[2],
                    'precipitation': result[3],
                    'humidity': result[4]
                }
                my_list.append(data)
            return True, my_list
        else:
            return False, []
    except mysql.connector.Error:
        logger.info("Errore di connessione DB get_user_topic_list")
        return False, []


def delete_sub(user, sub_list):
    try:
        conn = mysql.connector.connect(host='db-sub', user='root', password='', database='DBDS2')
        cursor = conn.cursor()
        locations_tuple = tuple(sub_list)
        in_clause = ', '.join(['%s'] * len(locations_tuple))
        query = f"DELETE FROM condition_notify WHERE email = %s AND location IN ({in_clause})"
        cursor.execute(query, (user,) + locations_tuple)
        conn.commit()
        cursor.close()
        conn.close()
        return True, True
    except mysql.connector.Error:
        logger.info("Errore di connessione DB delete_subscription")
        return False, False


def is_user_online(token):
    try:
        url = "https://usermanager:5000/is_token_valid"
        payload = {'token': token}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
        result = response.json()
        return result['success']
    except Exception as err:
        print(err)


def verifica_token(token):
    try:
        dati_json, firma_base64 = token.split('|', 1)
        data = json.loads(dati_json)
        exp_datetime = datetime.fromisoformat(data["exp"])
        if not is_user_online(token):
            logger.info("Token revocato %s", token)
            return False, "Errore, utilizzato un Token revocato"
        if datetime.utcnow() > exp_datetime:
            logger.info("Token scaduto %s", token)
            return False, "Token scaduto"
        else:
            firma_calcolata = hmac.new(chiave_segreta_usermanager.encode('utf-8'), dati_json.encode('utf-8'),
                                       hashlib.sha256).digest()
            firma_calcolata_base64 = base64.b64encode(firma_calcolata).decode('utf-8')
            if firma_calcolata_base64 == firma_base64:
                decrypted_data = json.loads(dati_json)
                return True, decrypted_data
            else:
                return False, "Firma non valida"
    except Exception as e:
        logger.info("Errore generico verifica_token")
        return False, str(e)


def verifica_notifier(token):
    try:
        dati_json, firma_base64 = token.split('|', 1)
        data = json.loads(dati_json)
        exp_datetime = datetime.fromisoformat(data["exp"])
        if datetime.utcnow() > exp_datetime:
            logger.info("Token scaduto %s", token)
            return False, "Token scaduto"
        else:
            firma_calcolata = hmac.new(chiave_segreta_notifier.encode('utf-8'), dati_json.encode('utf-8'),
                                       hashlib.sha256).digest()
            firma_calcolata_base64 = base64.b64encode(firma_calcolata).decode('utf-8')
            if firma_calcolata_base64 == firma_base64:
                decrypted_data = json.loads(dati_json)
                return True, decrypted_data
            else:
                return False, "Firma non valida"
    except Exception as e:
        logger.info("Errore generico verifica_token")
        return False, str(e)


def get_cities_list():
    try:
        conn = mysql.connector.connect(host='db-sub', user='root', password='', database='DBDS2')
        cursor = conn.cursor(dictionary=True)
        query = "SELECT name FROM city"
        cursor.execute(query)
        results = cursor.fetchall()
        if results:
            city_list = []
            for result in results:
                city_list.append(result['name'])
                cursor.close()
                conn.close()
            return True, city_list
    except mysql.connector.Error:
        logger.info("Errore di connessione DB get_cities_list")
        return None


app = Flask(__name__)


def validate_temperature(value):
    try:
        if value == "":
            return True
        if value[0] == '-':
            value = value[1:]
            if value.isdigit():
                temp = -float(value)
                return -10 <= temp <= 50
    except Exception:
        return False
    if value.isdigit():
        try:
            temp = float(value)
            return -10 <= temp <= 50
        except ValueError:
            return False
    else:
        return False


def validate_hp(value):
    try:
        if value == "":
            return True
        if '-' in value:
            return False
    except Exception:
        return False
    if value.isdigit():
        try:
            temp = float(value)
            return 0 <= temp <= 100
        except ValueError:
            return False
    else:
        return False


@app.route('/subscript', methods=['PUT'])
def subscript():
    data = request.get_json()
    token = data['token']
    state_, data_token = verifica_token(token)
    if state_:
        mail = data_token['email']
        location = data['location']
        t_min = data['t_min']
        t_max = data['t_max']
        hum = data['humidity']
        pre = data['precipitation']
        parametri = [location, t_min, t_max, hum, pre, mail]
        if validate_temperature(t_min) and validate_temperature(t_max):
            if t_max == "":
                v1 = float(56)
            else:
                v1 = float(t_max)

            if t_min == "":
                v2 = float(-11)
            else:
                v2 = float(t_min)
            if v2 < v1:
                if validate_hp(hum) and validate_hp(pre):
                    res, upd = insert_or_update_event(parametri)
                    if res:
                        if upd:
                            return jsonify({'success': True, 'message': 'La tua sottoscrizione è stata modificata con successo!'})
                        else:
                            return jsonify({'success': True, 'message': 'Sottoscrizione avvenuta con successo!'})
                    else:
                        return jsonify({'success': False, 'message': 'Errore durante la sottoscrizione! C002'})
                else:
                    return jsonify({'success': False, 'message': 'Parametri umidità o precipitazioni non validi non validi! C002'})
            else:
                return jsonify({'success': False, 'message': 'T_max è minore di t_min! '})
        else:
            return jsonify({'success': False, 'message': 'Parametri temperatura non validi! C002'})
    else:
        return jsonify({'success': False, 'message': 'Token non valido'})


@app.route('/get_subscriptions', methods=['GET'])
def get_subscriptions():
    data = request.get_json()
    token = data['token']
    state, data = verifica_token(token)
    if state:
        try:
            state, result = get_cities_list()
            if result:
                return jsonify({'success': True, 'message': 'Accesso riuscito!', 'topics': result})
            else:
                return jsonify({'success': False, 'message': "fallimento"})
        except Exception:
            logger.info("Errore generico get_subscriptions")
            return jsonify({'success': False, 'message': "Errore di accesso al DB"})
    else:
        return jsonify({'success': False, 'message': data})


@app.route('/my_subscriptions', methods=['GET'])
def my_subscriptions():
    data = request.get_json()
    val, data_ = verifica_token(data['token'])
    if val:
        state, my_list = get_user_topic_list(data_['email'])
        if state:
            if my_list is not None:
                return jsonify({'success': True, 'message': '', 'topics': my_list})
            else:
                return jsonify({'success': True, 'message': '', 'topics': my_list})
        else:
            return jsonify({'success': False, 'message': 'Errore nell\'ottenere l\'elenco delle sottoscrizioni'})
    else:
        return jsonify({'success': False, 'message': 'Token non valido'})


@app.route('/set_timestamp', methods=['PUT'])
def set_timestamp():
    try:
        data = request.get_json()
        val, _ = verifica_notifier(data['token'])
        if val:
            param1 = data['req']
            location = data['location']
            user = data['user']
            conn = mysql.connector.connect(host='db-sub', user='root', password='', database='DBDS2')
            cursor = conn.cursor()
            if param1 == "humidity":
                query = "UPDATE condition_notify SET timestamp_humidity = CURRENT_TIMESTAMP WHERE email = %s AND location = %s"
                cursor.execute(query, (user, location))
            if param1 == "precipitation":
                query = "UPDATE condition_notify SET timestamp_precipitation = CURRENT_TIMESTAMP WHERE email = %s AND location = %s"
                cursor.execute(query, (user, location))
            if param1 == "temperature":
                query = "UPDATE condition_notify SET timestamp_temperature = CURRENT_TIMESTAMP WHERE email = %s AND location = %s"
                cursor.execute(query, (user, location))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False})
    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return jsonify({'success': False})


@app.route('/get_user_list', methods=['GET'])
def get_user_list():
    try:
        data = request.get_json()
        val, _ = verifica_notifier(data['token'])
        if val:
            req = data['req']
            location = data['location']
            value = data['value']
            conn = mysql.connector.connect(host='db-sub', user='root', password='', database='DBDS2')
            cursor = conn.cursor()
            if req == "humidity":
                query = "SELECT email FROM condition_notify WHERE condition_notify.location = %s AND  %s > condition_notify.humidity AND TIMESTAMPDIFF(SECOND, condition_notify.timestamp_humidity, NOW()) >= 3600"
                cursor.execute(query, (location, value,))
            if req == "precipitation":
                query = "SELECT email FROM condition_notify WHERE condition_notify.location = %s AND  %s > condition_notify.precipitation  AND TIMESTAMPDIFF(SECOND, condition_notify.timestamp_precipitation, NOW()) >= 3600"
                cursor.execute(query, (location, value,))
            if req == "temperature":
                query = "SELECT email FROM condition_notify WHERE condition_notify.location = %s AND (%s < condition_notify.t_min OR %s > condition_notify.t_max) AND TIMESTAMPDIFF(SECOND, condition_notify.timestamp_temperature, NOW()) >= 3600"
                cursor.execute(query, (location, value, value,))
            results = cursor.fetchall()
            logger.info(results)
            cursor.close()
            conn.close()
            if results:
                users = [result[0] for result in results]
                return jsonify({'success': True, 'emails': users})
            else:
                return jsonify({'success': False, 'emails': []})
        else:
            return jsonify({'success': False, 'emails': []})
    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return jsonify({'success': False, 'emails': []})


@app.route('/remove_subscription', methods=['DELETE'])
def remove_subscription():
    data = request.get_json()
    sub_list = data['sub_list']
    token = data['token']
    state, data = verifica_token(token)
    s1, s2 = delete_sub(data['email'], sub_list)
    if state:
        if s1:
            if s2:
                return jsonify({'success': True, 'message': 'Sottoscrizione eliminata con successo'})
            else:
                return jsonify({'success': False, 'message': 'Non è stato trovata nessuna sottoscrizione da eliminare'})
        else:
            return jsonify({'success': False, 'message': 'Errore accesso al DB!'})
    else:
        return jsonify({'success': False, 'message': 'Token non valido!'})


@app.route('/send_performance', methods=['GET'])
def send_performance():
    ram, cpu = memory_usage()
    return jsonify({'success': True, 'ram': ram, 'cpu': cpu})


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Avvio Subscriber in corso...")

    ssl_cert = './cert.pem'
    ssl_key = './privkey.pem'
    generate_self_signed_cert(ssl_cert, ssl_key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        chiave_segreta_usermanager = os.environ['SIGN_KEY_USERMANAGER']
        chiave_segreta_notifier = os.environ['SIGN_KEY_NOTIFIER']
        PORT = os.environ['PORT']
        HOST = os.environ['HOST']
    except KeyError:
        logger.info("La variabile di ambiente non è stata impostata.")

    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    app.run(host=HOST, port=PORT, debug=True, ssl_context=context)
