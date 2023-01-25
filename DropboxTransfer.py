import base64
import datetime
import hashlib
import json
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
CONTENT = 'https://content.dropboxapi.com/'

parser = argparse.ArgumentParser(
    description='Dropbox Simple Transfer - dropbox file transfer CLI utility')

parser.add_argument('load', type=str, choices=['up', 'down'], help='"UP"load file or "DOWN"load')
parser.add_argument('src', type=str, help='Source file with path')
parser.add_argument('dst', type=str, help='Destination directory')
parser.add_argument('-d', '--debug', action='store_const', const=True, help='Turn on debug')
args = parser.parse_args()


if args.debug:
    logging.basicConfig(
        #format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.DEBUG)
else:
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        level=logging.ERROR)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
cons = logging.getLogger('errorlog')
cons.setLevel(logging.ERROR)
handler = logging.StreamHandler()
cons.addHandler(handler)


def load_config(section: str, option: str):
    """
    Loads configuration option from ini file
    """
    config = configparser.ConfigParser()
    logging.debug(f'Loading config: {option}')
    with open('settings.ini', 'a+') as configfile:
        config.read(configfile.name)
        #logging.debug(config.sections())
        if config.has_section(section):
            #logging.debug(config.options(section))
            if option in config.options(section):
                return config.get(section, option)
    return ''


def save_config(section: str, option: str, value: str):
    """
    Saves configuration options to ini file.
    """
    config = configparser.ConfigParser()
    with open('settings.ini', 'r') as configfile:
        config.read(configfile.name)
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
    Ensures if tokens are present, valid and not expired.
    Obtains new ones or refreshes them.
    """
    logging.info("Check tokens")
    tokens = {'access_token': load_config('Tokens', 'access_token'),
              'refresh_token': load_config('Tokens', 'refresh_token'),
              'expires_in': to_number(load_config('Tokens', 'expires_in')),
              }
    logging.debug(tokens)
    if tokens['access_token'] and tokens['refresh_token'] and tokens['expires_in']:
        if tokens['expires_in'] < time.time() + 30:
            logging.debug(f'Tokens should be refreshed: {tokens}')
            tokens = refresh_tokens(tokens)
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
    #tokens['refresh_token'] = response['refresh_token']
    tokens['expires_in'] = response['expires_in'] + time.time()
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
            'Невозможно открыть браузер. Пожалуйста пройдите по ссылке: ' + req.url
    print('Необходимо дать разрешение на доступ к вашим данным приложению Simple transfer.')
    for i in range(3):
        authorization_code = input('Введите код доступа из окна браузера:')
        logging.debug(f'Authorization code: {authorization_code}')

        params = {'code': authorization_code,
                  'grant_type': 'authorization_code',
                  'client_id': APP_KEY,
                  'code_verifier': code_verifier}
        logging.debug(f'Request parameters: {params}')
        # TODO try except ConnectionError
        try:
            req = requests.post(
                ENDPOINT + 'oauth2/token',
                #headers=HEADERS,
                params=params
            )
        except requests.exceptions.RequestException as error:
            #print(f"Проблема при подключении: {error}")
            raise Exception(f"Проблема при подключении: {error}")

        logging.debug(f'Response status code: {req.status_code}')
        logging.debug(f'Response plaintext: {req.text}')
        response = req.json()
        if req.status_code == HTTPStatus(200):
            break
        logging.error(f'Ошибка: {req.text}')
        if response['error'] == 'invalid_grant':
            logging.error(f'Введён неправильный код или он устарел.')
        else:
            logging.error('Что-то пошло не так')
            exit()
        if i == 2:
            logging.error('3 раза введён неправильный код')
            exit()

    if 'access_token' in response:
        tokens['access_token'] = response['access_token']
    else:
        tokens['access_token'] = ""
    if 'refresh_token' in response:
        tokens['refresh_token'] = response['refresh_token']
    else:
        tokens['refresh_token'] = ""
    if 'expires_in' in response:
        tokens['expires_in'] = response['expires_in'] + time.time()
    else:
        tokens['expires_in'] = None

    for key, value in tokens.items():
        logging.debug(f'{key}: {value}')
        save_config('Tokens', key, value)
    #logging.debug(f'Access token: {access_token}')
    #logging.debug(f'Refresh token: {refresh_token}')
    #logging.debug(f'Expires in: {expires_in}')

    return tokens

def check_eligible_operations():
    pass


def check_local_path(file_path):
    #file_path = r"c:\Documents\Projects\Development\Studies\Test assignments\Dropbox transfer\file.rar"
    #file_path = r"c:/Documents/Projects/Development/Studies/Test assignments/Dropbox transfer/file.rar"
    #file_path = r"/file.rar"

    result = re.findall("r(/(.|[\r\n])*)|(ns:[0-9]+(/.*)?)|(id:.*)", file_path)
    print(result)
    return file_path
    pass


def check_remote_URL():
    pass

def check_file_permissions():
    pass

def check_if_file_present():
    pass

def download():
    pass


def upload(tokens):
    print(args.src)
    print(args.dst)
    file_path = check_local_path(args.src)

    headers = {'Authorization': f'Bearer {tokens["access_token"]}',
               'Content-Type': 'application/octet-stream',
               'Dropbox-API-Arg': json.dumps({
                   "autorename": True,
                   "mode": "add",
                   "mute": False,
                   "path": args.dst,
                   "strict_conflict": False
               })
               }
    params = {}
    # TODO: provide hash to check if upload was correct
    # TODO: implement progress bar
    #with open('file.rar', 'rb') as f:
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        raise Exception(f"Файл не найден: {file_path} \n\r"
                        f"Проверьте корректность пути и имени файла.")
    except PermissionError:
        raise Exception(f"Ошибка доступа к файлу: {file_path} \n\r"
                        f"Необходимы права на чтение файла.")
    print('Выгрузка файла на сервер Dropbox')
    try:
        req = requests.post(
            CONTENT + '2/files/upload',
            headers=headers,
            params=params,
            data=data,
        )
    except requests.exceptions.RequestException as error:
        raise Exception(f"Проблема при подключении: {error}")

    logging.debug(f'Response status code: {req.status_code}')
    logging.debug(f'Response plaintext: {req.text}')
    if req.status_code != 200:
        if "did not match pattern" in req.text:
            raise Exception(f"Ошибка выгрузки: {req.text}\n"
                            f"Неправильный путь для файла на сервере: {args.dst}")
        #response = req.json()
        #if response['error_summary'] == 'path/conflict/file/...':
        #    raise Exception(f"По заданному пути файл уже есть: {req.text}")
        else:
            raise Exception(f"Проблема при выгрузке файла: {req.text}")
    print("Файл успешно выгружен")



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
    print(args)

    #file_path = check_local_path(args.src)
    #print(file_path)

    try:
        tokens = check_tokens()
        if args.load == 'up':
            result = upload(tokens)
#
    except Exception as error:
        message = f'Сбой в работе программы: {error}'
        logging.error(message)
    print('выход')


if __name__ == '__main__':
    main()

