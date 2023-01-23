import base64
import hashlib
import os
import re
import subprocess
import sys
import logging
import configparser

import requests
import argparse
from http import HTTPStatus
#from oauthlib.oauth2 import WebApplicationClient
from dotenv import load_dotenv

load_dotenv()

APP_KEY = os.getenv('APP_KEY')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

DROPBOX_CLIENT_SECRET = os.getenv('CLIENT_SECRET')
#HEADERS = {'Authorization': f'Bearer {DROPBOX_TOKEN}'}
ENDPOINT = 'https://api.dropboxapi.com/'


logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
cons = logging.getLogger('errorlog')
cons.setLevel(logging.ERROR)
handler = logging.StreamHandler()
cons.addHandler(handler)


def load_config():
    config = configparser.ConfigParser()
    config.read('settings.ini')
    if not config.sections():
        with open('settings.ini', 'w') as configfile:  # save
            config.write(configfile)
    print(config)

def check_tokens():
    return False
    pass

def obtain_tokens():
    if 'args' == 'test':
        dropbox_token = os.getenv('DROPBOX_TOKEN')
    else:
        dropbox_token = None
    if dropbox_token is None:
        logging.info("Запрос к API")
        print(APP_KEY)
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        print(code_verifier)
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
        print(code_verifier, len(code_verifier))
        code_challenge_method = 'S256'
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        print(code_challenge)
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        print(code_challenge)
        code_challenge = code_challenge.replace('=', '')
        print(code_challenge)
        params = {'client_id': APP_KEY,
                  'response_type': 'code',
                  'code_challenge': code_challenge,
                  'code_challenge_method': code_challenge_method,
                  'token_access_type': 'offline'
                  }
        # code_challenge = < CHALLENGE > & code_challenge_method = < METHOD >
        req = requests.Request('GET', 'https://www.dropbox.com/oauth2/authorize', params=params).prepare()
        logging.info('URL to be executed: ' + req.url)
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
        authorization_code = input()
        print(authorization_code)

        #ufp5E2ouSmAAAAAAAAAAHkzFjo6VWRsNj4cnZXt0xJM
        params = {'code': authorization_code,
                  'grant_type': 'authorization_code',
                  'client_id': APP_KEY,
                  'code_verifier': code_verifier}
        print(params)
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
        print(req.status_code)
        print(req.text)
        response = req.json()
        access_token = response['access_token']
        refresh_token = response['refresh_token']
        print(access_token)
        print(refresh_token)
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
    load_config()

    if not check_tokens():
        obtain_tokens()

    pass


if __name__ == '__main__':
    main()

