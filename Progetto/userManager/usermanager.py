import logging
import os
import ssl
import hmac
import json
import base64
import hashlib
import psutil
import mysql.connector
from OpenSSL import crypto
from passlib.hash import argon2
from argon2 import PasswordHasher
from datetime import datetime, timedelta
from flask import Flask, request, jsonify


app = Flask(__name__)


def invalidate_token(token):
    if token in session_list:
        session_list.remove(token)


def generate_self_signed_cert(cert_file, key_, days_valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "UserManager"
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


def genera_token(admin, username, email):
    data = {
        'email': email,
        'username': username,
        'create': datetime.utcnow().isoformat(),
        'exp': (datetime.utcnow() + timedelta(days=1)).isoformat()
    }
    dati_json = json.dumps(data)
    firma_hmac = hmac.new(chiave_segreta.encode('utf-8'), dati_json.encode('utf-8'), hashlib.sha256).digest()
    if admin:
        firma_hmac = hmac.new(chiave_segreta_admin.encode('utf-8'), dati_json.encode('utf-8'), hashlib.sha256).digest()
    firma_base64 = base64.b64encode(firma_hmac).decode('utf-8')
    token = f"{dati_json}|{firma_base64}"
    return token


def verifica_token(token):
    try:
        dati_json, firma_base64 = token.split('|', 1)
        data = json.loads(dati_json)
        exp_datetime = datetime.fromisoformat(data["exp"])
        if token not in session_list:
            return False, "Errore, utilizzato un Token revocato"
        if datetime.utcnow() > exp_datetime:
            return False, "Token scaduto"
        else:
            firma_calcolata = hmac.new(chiave_segreta.encode('utf-8'), dati_json.encode('utf-8'),
                                       hashlib.sha256).digest()
            firma_calcolata_base64 = base64.b64encode(firma_calcolata).decode('utf-8')
            if firma_calcolata_base64 == firma_base64:
                decrypted_data = json.loads(dati_json)
                return True, decrypted_data
            else:
                return False, "Firma non valida"
    except Exception as e:
        logger.info("Errore di connessione al database: %s", e)
        return False, str(e)


def verifica_credenziali(admin, username, password):
    try:
        conn = mysql.connector.connect(host='db', user='root', password='', database='DBDS')
        cursor = conn.cursor()
        query = "SELECT password FROM user WHERE username = %s"
        if admin:
            query = "SELECT password FROM user WHERE username = %s AND isAdmin = 1"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            stored_hashed_password = result[0]
            ph = PasswordHasher()
            try:
                state = ph.verify(stored_hashed_password, password)
                if state:
                    return True, True
            except Exception as err:
                logger.info("Credenziali non valide: %s", err)
                return True, False
        else:
            return True, False
    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return False, False


def getEmail(username):
    try:
        conn = mysql.connector.connect(host='db', user='root', password='', database='DBDS')
        cursor = conn.cursor()
        query = "SELECT email FROM user WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return True, result[0]
        else:
            return True, False
    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return False, False


def verifica_data(data, data2):
    try:
        conn = mysql.connector.connect(host='db', user='root', password='', database='DBDS')
        cursor = conn.cursor()
        if data == "username":
            query = "SELECT * FROM user WHERE username = %s"
        elif data == "email":
            query = "SELECT * FROM user WHERE email = %s"
        else:
            return False, False
        cursor.execute(query, (data2,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return True, True
        else:
            return True, False
    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return False, False


def registration(username, password, email):
    try:
        hashed_password = argon2.using(rounds=2, memory_cost=102400, parallelism=2).hash(password)
        conn = mysql.connector.connect(host='db', user='root', password='', database='DBDS')
        cursor = conn.cursor()
        query = "INSERT INTO user (username, password, email) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, hashed_password, email))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return False


def update_user(new_val, username, data):
    try:
        conn = mysql.connector.connect(host='db', user='root', password='', database='DBDS')
        cursor = conn.cursor()
        query = None
        if data == "username":
            query = "UPDATE user SET username = %s WHERE username = %s"
        if data == "email":
            query = "UPDATE user SET email = %s WHERE username = %s"
        if data == "password":
            new_val = argon2.using(rounds=2, memory_cost=102400, parallelism=2).hash(new_val)
            query = "UPDATE user SET password = %s WHERE username = %s"
        cursor.execute(query, (new_val, username))
        conn.commit()
        cursor.close()
        conn.close()
        return True

    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return False


def verifica(username, email):
    try:
        conn = mysql.connector.connect(host='db', user='root', password='', database='DBDS')
        cursor = conn.cursor()
        query = "SELECT * FROM user WHERE username = %s OR email = %s"
        cursor.execute(query, (username, email))
        result = cursor.fetchall()
        cursor.close()
        conn.close()
        if result:
            return True, True
        else:
            return True, False
    except mysql.connector.Error as err:
        logger.info("Errore di connessione al database: %s", err)
        return False, False


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    s1, s2 = verifica_credenziali(False, username, password)
    if s1:
        if s2:
            email = getEmail(username)
            if email:
                s3, email = getEmail(username)
                if s3:
                    if email:
                        token = genera_token(False, username, email)
                        session_list.append(token)
                        return jsonify({'success': True, 'email': email, 'token': token, 'message': 'Accesso riuscito!'})
                    else:
                        return jsonify({'success': False, 'message': 'Errore acquisizione email'})
                else:
                    return jsonify({'success': False, 'message': 'Errore nell''accesso al DB C02'})
            else:
                return jsonify({'success': False, 'message': 'Errore accesso DB C03'})
        else:
            return jsonify({'success': False, 'message': 'Credenziali non valide!'})
    else:
        return jsonify({'success': False, 'message': 'Errore nell''accesso al DB C01'})


@app.route('/login_admin', methods=['POST'])
def login_admin():
    data = request.get_json()
    username = data['username']
    password = data['password']
    s1, s2 = verifica_credenziali(True, username, password)
    if s1:
        if s2:
            email = getEmail(username)
            if email:
                s3, email = getEmail(username)
                if s3:
                    if email:
                        token = genera_token(True, username, email)
                        session_list.append(token)
                        return jsonify({'success': True, 'email': email, 'token': token, 'message': 'Accesso riuscito!'})
                    else:
                        return jsonify({'success': False, 'message': 'Errore acquisizione email'})
                else:
                    return jsonify({'success': False, 'message': 'Errore nell''accesso al DB C02'})
            else:
                return jsonify({'success': False, 'message': 'Errore accesso DB C03'})
        else:
            return jsonify({'success': False, 'message': 'Credenziali non valide!'})
    else:
        return jsonify({'success': False, 'message': 'Errore nell''accesso al DB C01'})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']
    s1, s2 = verifica(username, email)
    if s1:
        if s2:
            return jsonify({'success': False, 'message': 'Utente o email gia registrati'})
        else:
            s3 = registration(username, password, email)
            if s3:
                return jsonify({'success': True, 'message': 'Registrazione riuscita'})
            else:
                return jsonify({'success': False, 'message': 'Errore nel DB COD: N02'})
    else:
        return jsonify({'success': False, 'message': 'Errore nel DB COD: N01'})


@app.route('/update', methods=['PUT'])
def update():
    data = request.get_json()
    new_value = data['val_new']
    update = data['update']
    token = data['token']
    password = data['password']
    s1, data_token = verifica_token(token)
    if s1:
        username = data_token['username']
        s6, s7 = verifica_credenziali(False, username, password)
        if s7:
            if s6:
                if update == 'password':
                    s8 = update_user(new_value, username, update)
                    if s8:
                        s9, email = getEmail(username)
                        if s9:
                            if email:
                                token = genera_token(False, username, email)
                                invalidate_token(data['token'])
                                session_list.append(token)
                                return jsonify({'success': True, 'token': token, 'message': 'Password modificata con successo'})
                            else:
                                return jsonify({'success': False, 'message': 'Errore di accesso al DB C07'})
                        else:
                            return jsonify({'success': False, 'message': 'Errore di accesso al DB C08'})
                    else:
                        return jsonify({'success': False, 'message': 'Errore di accesso al DB CO4'})
                else:
                    s3, s4 = verifica_data(update, new_value)
                    if s3:
                        if s4:
                            return jsonify({'success': False, 'message': 'credenziali usate da un altro utente'})
                        else:
                            s5 = update_user(new_value, username, update)
                            if s5:
                                if update == "username":
                                    s10, email = getEmail(new_value)
                                    if s10:
                                        if email:
                                            token = genera_token(False, new_value, email)
                                            invalidate_token(data['token'])
                                            session_list.append(token)
                                            return jsonify({'success': True, 'token': token, 'message': 'Credenziali modificate con successo'})
                                        else:
                                            return jsonify({'success': False, 'message': 'Errore di accesso al DB C06'})
                                    else:
                                        return jsonify({'success': False, 'message': 'Errore di accesso al DB C09'})
                                if update == "email":
                                    token = genera_token(False, username, new_value)
                                    invalidate_token(data['token'])
                                    session_list.append(token)
                                    return jsonify({'success': True, 'token': token, 'message': 'Credenziali modificate con successo'})
                            else:
                                return jsonify({'success': False, 'message': 'Errore di accesso al DB C02'})
                    else:
                        return jsonify({'success': False, 'message': 'Errore di accesso al DB C01'})
            else:
                return jsonify({'success': False, 'message': 'Errore di accesso al DB C03!'})
        else:
            return jsonify({'success': False, 'message': 'Credenziali errate!'})
    else:
        invalidate_token(data['token'])
        return jsonify({'success': False, 'message': 'Token scaduto o compromesso!'})


@app.route('/send_performance', methods=['GET'])
def send_performance():
    ram, cpu = memory_usage()
    return jsonify({'success': True, 'ram': ram, 'cpu': cpu})


@app.route('/online_user', methods=['GET'])
def online_user():
    try:
        count = len(session_list)
    except Exception as err:
        logger.info("Errore durante il conteggio degli utenti online: %s", err)
        count = -1
    return jsonify({'success': True, 'online_user': count})


@app.route('/is_token_valid', methods=['GET'])
def is_token_valid():
    try:
        data = request.get_json()
        return jsonify({'success': data['token'] in session_list})
    except Exception as err:
        logger.info(err)


@app.route('/logout', methods=['POST'])
def logout():
    try:
        data = request.get_json()
        invalidate_token(data['token'])
        return jsonify({'success': True, 'message': "Logout effettuato correttamente"})
    except Exception as err:
        logger.info(err)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    session_list = []
    ssl_cert = './cert.pem'
    ssl_key = './privkey.pem'
    generate_self_signed_cert(ssl_cert, ssl_key)
    try:
        chiave_segreta = os.environ.get('SIGN_KEY_USERMANAGER')
        chiave_segreta_admin = os.environ.get('SIGN_KEY_USERMANAGER_ADMIN')
        PORT = os.environ.get('PORT')
        HOST = os.environ.get('HOST')
        logger.info(PORT)
        logger.info(HOST)
    except Exception as e:
        logger.info(e)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    try:
        app.run(host=HOST, port=PORT, debug=True, ssl_context=context)
    except Exception as e:
        logger.info(e)
