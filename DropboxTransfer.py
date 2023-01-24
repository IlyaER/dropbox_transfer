import base64
import datetime
import hashlib
import os
import re
import subprocess
import sys
import logging
import configparser
import time

import requests
import argparse
from http import HTTPStatus
#from oauthlib.oauth2 import WebApplicationClient
from dotenv import load_dotenv

load_dotenv()

APP_KEY = os.getenv('APP_KEY')

#HEADERS = {'Authorization': f'Bearer {DROPBOX_TOKEN}'}
ENDPOINT = 'https://api.dropboxapi.com/'


logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    level=logging.DEBUG) # INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
cons = logging.getLogger('errorlog')
cons.setLevel(logging.ERROR)
handler = logging.StreamHandler()
cons.addHandler(handler)


def load_config(section, option):
    """
    Loads configuration option from ini file
    """
    config = configparser.ConfigParser()
    with open('settings.ini', 'r') as configfile:
        config.read('settings.ini')
        logging.debug(config.sections())
        if config.has_section(section):
            logging.debug(config.options(section))
            if option in config.options(section):
                return config.get(section, option)
        return ''

    #logging.debug(config.items())
    #return check_tokens(config.sections())
    #return config.sections()
    #if not config.sections():
    #    return False
    #else:
    #    return config.sections()
        #with open('settings.ini', 'w') as configfile:  # save
        #    config.write(configfile)


def save_config(section: str, option: str, value: str):
    config = configparser.ConfigParser()
    config.read('settings.ini')
    if not config.has_section(section):
        config.add_section(section)
    config.set(section, option, str(value))
    with open('settings.ini', 'w') as configfile:  # save
        config.write(configfile)


def to_number(char):
    try:
        return float(char)
    except ValueError:
        logging.info('Expected value is not number')
        return ''



def check_tokens():
    """
    Ensures if tokens are present, valid and not expired
    """
    logging.info("Проверка токенов")
    tokens = {'access_token': load_config('Tokens', 'access_token'),
              'refresh_token': load_config('Tokens', 'refresh_token'),
              'expires_in': to_number(load_config('Tokens', 'expires_in')),
              }
    if tokens['access_token'] and tokens['refresh_token'] and tokens['expires_in']:
        if tokens['expires_in'] < time.time() + 30:
            logging.debug(f'Tokens should be refreshed: {tokens}')
            tokens = refresh_tokens(tokens)

        return tokens
    else:
        logging.debug(f'Tokens are missing, obtaining new: {tokens}')
        tokens = obtain_tokens(tokens)
    return tokens


def refresh_tokens(tokens):
    params = {'grant_type': 'refresh_token',
              'client_id': APP_KEY,
              'refresh_token': tokens['refresh_token']}
    logging.debug(f'Request parameters: {params}')
    req = requests.post(ENDPOINT + 'oauth2/token', params=params)
    logging.debug(f'Response status code: {req.status_code}')
    logging.debug(f'Response plaintext: {req.text}')
    if req.status_code != HTTPStatus(200):
        logging.info(f'Failed to refresh tokens, obtaining new ones')
        return obtain_tokens(tokens)
    response = req.json()
    tokens['access_token'] = response['access_token']
    tokens['refresh_token'] = response['refresh_token']
    tokens['expires_in'] = response['expires_in']
    for key, value in tokens.items():
        logging.debug(f'{key}: {value}')
        save_config('Tokens', key, value)
    return tokens



def challenge_generator():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    logging.debug(f'Code verifier: {code_verifier}')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
    logging.debug(f'Code verifier: {code_verifier}, {len(code_verifier)}')
    code_challenge_method = 'S256'
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    logging.debug(f'Code challenge: {code_challenge}')
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    logging.debug(f'Code challenge: {code_challenge}')
    code_challenge = code_challenge.replace('=', '')
    logging.debug(f'Code challenge: {code_challenge}')
    return code_verifier, code_challenge_method, code_challenge


def obtain_tokens(tokens):
    #if 'args' == 'test':
    #    dropbox_token = os.getenv('DROPBOX_TOKEN')
    #else:
    #    dropbox_token = None
    #if True: # config.access_token is None:

    logging.info("Request API to obtain tokens")
    logging.debug(APP_KEY)
    code_verifier, code_challenge_method, code_challenge = challenge_generator()

    params = {'client_id': APP_KEY,
              'response_type': 'code',
              'code_challenge': code_challenge,
              'code_challenge_method': code_challenge_method,
              'token_access_type': 'offline'
              }
    # code_challenge = < CHALLENGE > & code_challenge_method = < METHOD >
    req = requests.Request('GET', 'https://www.dropbox.com/oauth2/authorize', params=params).prepare()
    logging.debug('URL to be executed: ' + req.url)
    #url = f'https://www.dropbox.com/oauth2/authorize?client_id={APP_KEY}&response_type=code&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}&token_access_type=offline'
    if sys.platform == 'win32':
        #pass # TODO
        os.startfile(req.url)
    elif sys.platform == 'darwin':
        subprocess.Popen(['open', req.url])
    else:
        try:
            subprocess.Popen(['xdg-open', req.url])
        except OSError:
            print
            'Please open a browser on: ' + req.url
    print('Необходимо дать разрешение на доступ к вашим данным приложению Simple transfer.')
    authorization_code = input('Введите код доступа из окна браузера:')
    logging.debug(f'Authorization code: {authorization_code}')

    #ufp5E2ouSmAAAAAAAAAAHkzFjo6VWRsNj4cnZXt0xJM
    params = {'code': authorization_code,
              'grant_type': 'authorization_code',
              'client_id': APP_KEY,
              'code_verifier': code_verifier}
    logging.debug(f'Request parameters: {params}')
    req = requests.post(ENDPOINT + 'oauth2/token', params=params)
    #req = requests.Request('POST', ENDPOINT + 'oauth2/token', params=params)
    #prepared = req.prepare()
    #print('{}\n{}\r\n{}\r\n\r\n{}'.format(
    #    '-----------START-----------',
    #    prepared.method + ' ' + req.url,
    #    '\r\n'.join('{}: {}'.format(k, v) for k, v in prepared.headers.items()),
    #    prepared.body,
    #))
    #print(prepared)
    logging.debug(f'Response status code: {req.status_code}')
    logging.debug(f'Response plaintext: {req.text}')
    response = req.json()
    tokens['access_token'] = response['access_token']
    tokens['refresh_token'] = response['refresh_token']
    tokens['expires_in'] = response['expires_in']
    for key, value in tokens.items():
        logging.debug(f'{key}: {value}')
        save_config('Tokens', key, value)
    #logging.debug(f'Access token: {access_token}')
    #logging.debug(f'Refresh token: {refresh_token}')
    #logging.debug(f'Expires in: {expires_in}')

    return tokens
    #print(access_token.json())
    #sl.BXehOSw2HDq_j_jTEYArqvnV1_K0TImobaaqoieCLKupzSjNhBxFrrToIWvOXxlagi7npXWAXRW6gTF_WRyQoA4hme2VVAhVIetkhkwEGO3_FO9jN5YoxREvsj0dAxfM - IGqSRc
    #dropbox_token
    pass
    'https://www.dropbox.com/oauth2/authorize?client_id=<APP_KEY>&response_type=code'


def check_eligible_operations():
    pass

def check_local_URL():
    pass

def check_remote_URL():
    pass

def check_file_permissions():
    pass

def check_if_file_present():
    pass

def download():
    pass

def upload():
    pass

def check_if_downloadable(url):
    """
    Does the url contain a downloadable resource
    """
    h = requests.head(url, allow_redirects=True)
    header = h.headers
    content_type = header.get('content-type')
    if 'text' in content_type.lower():
        return False
    if 'html' in content_type.lower():
        return False
    return True


def return_status():
    pass


def check_arguments():
    pass


def main():
    #config = load_config()
    #print(config)
    tokens = check_tokens()


    pass


if __name__ == '__main__':
    main()

