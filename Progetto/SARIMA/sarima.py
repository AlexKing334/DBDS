import os
import ssl
from io import BytesIO
import psutil
import base64
from OpenSSL import crypto
from flask import jsonify
import requests
import json
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from statsmodels.tsa.statespace.sarimax import SARIMAX
from flask import Flask, request
from statsmodels.tsa.stattools import adfuller
from urllib3.exceptions import InsecureRequestWarning

app = Flask(__name__)


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


def verifica_token(token):
    try:
        url = "https://slamanager:7000/is_token_valid"
        payload = {'token': token}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(ssl_cert, ssl_key), verify=False)
        result = response.json()
        return result['success']
    except Exception as err:
        logger.info(err)


def memory_usage():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cpu_info = psutil.cpu_percent(interval=1, percpu=False)
    return mem_info.rss, cpu_info


def stationarity(values_data):
    stationarityTest = adfuller(values_data.dropna(), regression='c', autolag='AIC')
    if stationarityTest[1] <= 0.05:
        return True
    else:
        return False


def seasonality(series, threshold=0.05):
    result_adf = adfuller(series)
    p_value = result_adf[1]
    return p_value < threshold


@app.route('/send_performance', methods=['GET'])
def send_performance():
    ram, cpu = memory_usage()
    return jsonify({'success': True, 'ram': ram, 'cpu': cpu})


@app.route('/prediction', methods=['GET'])
def prediction():
    try:
        data = request.get_json()
        if verifica_token(data['token']):
            name = data["name"]
            threshold = int(data["threshold"])
            PROMETHEUS = 'http://prometheus:9090/'
            now = datetime.now()
            one_hour_ago = now - timedelta(hours=1)

            response = requests.get(PROMETHEUS + 'api/v1/query_range', params={
                'query': name,
                'start': one_hour_ago.timestamp(),
                'end': now.timestamp(),
                'step': '10'
            })
            data = json.loads(response.text)
            time_series_data = data['data']['result'][0]['values']
            df = pd.DataFrame(time_series_data, columns=['timestamp', 'value'])
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            df.set_index('timestamp', inplace=True)
            df['value'] = df['value'].astype(float)
            df = df.asfreq('10S', method='pad')
            model = SARIMAX(df['value'], order=(1, 1, 1), seasonal_order=(1, 1, 1, 12))
            model = model.fit(disp=False)
            plt.clf()
            plt.plot(df.index, df['value'], label=name, color='blue')
            num_punti_futuri = round(5 * 60/10)
            try:
                forecast = model.get_forecast(steps=num_punti_futuri)
                yhat = forecast.predicted_mean
                forecast_index = pd.date_range(df.index[-1], periods=num_punti_futuri + 1, freq='10S')[1:]
                join_index = df.index[-1]
                plt.plot(df.loc[df.index <= join_index].index, df.loc[df.index <= join_index]['value'],
                         label=name, color='blue')
                plt.plot([df.index[-1], forecast_index[0]], [df['value'].iloc[-1], yhat[0]], color='blue')
                plt.plot(forecast_index, yhat, label=name+'_PREDICT', color='red')
                plt.xlabel('Timestamp')
                plt.ylabel('Value')
                plt.legend()
                img_buffer = BytesIO()
                plt.savefig(img_buffer, format='png')
                img_buffer.seek(0)
                img_str = base64.b64encode(img_buffer.read()).decode('utf-8')
            except KeyError:
                logger.info('Errore: impossibile fare previsioni per', num_punti_futuri, 'punti dati.')
                return jsonify({'success': False, 'message': f'Errore durante la previsione'})
            num_violazioni = np.sum(yhat.astype(float) > float(threshold))
            prob_violazione = num_violazioni / len(yhat) if len(yhat) > 0 else 0
            logger.info("percentual %s", prob_violazione)
            return jsonify({'success': True, 'message': str(prob_violazione), 'plot': img_str})
        else:
            return jsonify({'success': False, 'message': 'Token non valido'})
    except Exception as err:
        return jsonify({'success': False, 'message': f'Errore generico durante la previsione: {err}'})


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    ssl_cert = './cert.pem'
    ssl_key = './privkey.pem'
    generate_self_signed_cert(ssl_cert, ssl_key)
    try:
        HOST = os.environ['HOST']
        PORT = os.environ['PORT']
    except KeyError:
        logger.info("Le variabili di ambiente non sono state impostate correttamente!")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    app.run(host=HOST, port=PORT, debug=True, use_reloader=False, ssl_context=context)
