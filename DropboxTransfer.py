import argparse
import base64
import configparser
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from http import HTTPStatus

import requests

APP_KEY = 'h8ekx0d4sx02uzg'

API = 'https://api.dropboxapi.com/'
CONTENT = 'https://content.dropboxapi.com/'

parser = argparse.ArgumentParser(
    description='Dropbox Simple Transfer - dropbox file transfer CLI utility')

parser.add_argument(
    'load',
    type=str,
    choices=['up', 'down'],
    help='"UP"load file or "DOWN"load'
)
parser.add_argument(
    'src',
    type=str,
    help='Source file with path'
)
parser.add_argument(
    'dst',
    nargs='?',
    type=str,
    help='Destination directory'
)
parser.add_argument(
    '-d',
    '--debug',
    action='store_const',
    const=True,
    help='Turn on debug'
)
args = parser.parse_args()

if args.debug:
    logging.basicConfig(
        #  format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
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
        if config.has_section(section):
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
    with open('settings.ini', 'w') as configfile:
        config.write(configfile)


def to_number(char):
    try:
        return float(char)
    except ValueError:
        logging.warning('Expected value is not number')
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
    if (tokens['access_token']
            and tokens['refresh_token']
            and tokens['expires_in']):
        if tokens['expires_in'] < time.time() + 30:
            logging.debug(f'Tokens should be refreshed: {tokens}')
            return refresh_tokens(tokens)
        return tokens
    logging.debug(f'Tokens are missing, obtaining new: {tokens}')
    return obtain_tokens(tokens)


def refresh_tokens(tokens):
    """
    Updates tokens using PKCE code flow's refresh token to obtain
    new access token.
    """
    params = {'grant_type': 'refresh_token',
              'client_id': APP_KEY,
              'refresh_token': tokens['refresh_token']}
    logging.debug(f'Request parameters: {params}')
    req = requests.post(API + 'oauth2/token', params=params)
    logging.debug(f'Response status code: {req.status_code}')
    logging.debug(f'Response plaintext: {req.text}')
    if req.status_code != HTTPStatus(200):
        logging.info('Failed to refresh tokens, obtaining new ones')
        return obtain_tokens(tokens)
    response = req.json()
    tokens['access_token'] = response['access_token']
    tokens['expires_in'] = response['expires_in'] + time.time()
    for key, value in tokens.items():
        logging.debug(f'{key}: {value}')
        save_config('Tokens', key, value)
    return tokens


def challenge_generator():
    """
    Generates random base64-safe sequence and a S256 hash as code challenge
    for server-side client verification to protect from MITM attacks.
    """
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
    """
    Obtains tokens for OAuth 2 authorization of the app using PKCE flow.
    """
    logging.info("Request API to obtain tokens")
    logging.debug(APP_KEY)

    (code_verifier,
     code_challenge_method,
     code_challenge) = challenge_generator()

    params = {'client_id': APP_KEY,
              'response_type': 'code',
              'code_challenge': code_challenge,
              'code_challenge_method': code_challenge_method,
              'token_access_type': 'offline'
              }
    req = requests.Request(
        'GET',
        'https://www.dropbox.com/oauth2/authorize',
        params=params).prepare()
    logging.debug('URL to be executed: ' + req.url)
    print('Необходимо дать разрешение на доступ к вашим данным '
          'приложению Simple transfer.')
    if sys.platform == 'win32':
        os.startfile(req.url)
    elif sys.platform == 'darwin':
        subprocess.Popen(['open', req.url])
    else:
        try:
            subprocess.Popen(['xdg-open', req.url])
        except OSError:
            print('Невозможно открыть браузер. '
                  'Пожалуйста пройдите по ссылке: \n\r' + req.url)
    print("Если вы случайно закрыли окно браузера, "
          "пожалуйста пройдите по ссылке: \n\r" + req.url)
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
                API + 'oauth2/token',
                params=params
            )
        except (requests.exceptions.RequestException, ConnectionError) as error:
            logging.error(f"Проблема при подключении: {error}")
            raise

        logging.debug(f'Response status code: {req.status_code}')
        logging.debug(f'Response plaintext: {req.text}')
        response = req.json()
        if req.status_code == HTTPStatus(200):
            break
        logging.error(f'Ошибка: {req.text}')
        if 'invalid_grant' in response['error']:
            logging.error('Введён неправильный код или он устарел.')
        elif 'invalid_request' in response['error']:
            logging.error('Код не должен быть пустым.')
        else:
            raise ConnectionRefusedError('Что-то пошло не так')
        if i == 2:
            raise ValueError('3 раза введён неправильный код')

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

    return tokens


def check_local_path(path):
    """
    Validates local file/folder path.
    """
    if args.load == 'up' and os.path.isfile(path):
        return path

    if args.load == 'down':  # and os.path.exists(path):
        pattern = r'.*(\\|/)'
        remote_file_name = re.sub(pattern, '', args.src)
        if not path:
            logging.debug(f"File_name: {remote_file_name}")
            return remote_file_name
        logging.debug(os.path.isdir(path))
        logging.debug(os.path.isfile(path))
        logging.debug(path)
        if path.endswith(os.sep):
            return path + remote_file_name
        elif path.startswith(os.sep):
            return path[1:]
        return os.path.normpath(path)
    logging.error(f"Файл не найден: {path} \n\r"
                    f"Проверьте корректность пути и имени файла.")
    raise FileNotFoundError


def check_remote_URL(path):
    """
    Validates remote URL.
    """
    pattern = r'.*(\\|/)'
    if args.load == 'up':
        if not path:
            path = "/"
        local_file_name = re.sub(pattern, '', args.src)
        logging.debug(f"File_name: {local_file_name}")
        logging.debug(
            f"Path ends with file name: {path.endswith(local_file_name)}"
        )
        if path.endswith("/"):
            return path + local_file_name
    return path


def download(tokens):
    """
    Downloads file from remote source.
    """
    logging.debug(f"Source:{args.src}")
    path = check_remote_URL(args.src)
    logging.debug(f"Destination:{args.dst}")
    file_path = check_local_path(args.dst)
    logging.debug(f"Destination:{file_path}")

    headers = {'Authorization': f'Bearer {tokens["access_token"]}',
               'Content-Type': 'application/octet-stream',
               'Dropbox-API-Arg': json.dumps({
                   "path": path,
               })
               }
    params = {}
    # TODO: validate hash to see if download was correct
    # TODO: implement progress bar
    print('Загрузка файла с сервера Dropbox')
    try:
        with open(file_path, 'wb') as file:
            try:
                req = requests.post(
                    CONTENT + '2/files/download',
                    headers=headers,
                    params=params,
                )
            except (requests.exceptions.RequestException, ConnectionError) as error:
                logging.error(f"Проблема при подключении: {error}")
                raise
            logging.debug(f'Response status code: {req.status_code}')
            if req.status_code != 200:
                if "did not match pattern" in req.text:
                    logging.error(
                        f"Ошибка загрузки: {req.text}\n"
                        f"Неправильный путь для файла на сервере: {args.dst}"
                    )
                    raise ValueError
                try:
                    response = req.json()
                except ValueError:
                    logging.error(
                        f"Проблема при загрузке файла: {req.text}"
                    )
                    raise
                if "path/not_file/" in response['error_summary']:
                    logging.error(
                        f"Указанный путь не является "
                        f"файлом на сервере: {req.text}"
                    )
                    raise IsADirectoryError
                elif "path/not_found/" in response['error_summary']:
                    logging.error(
                        f"Неверный путь к файлу на сервере, "
                        f"такого файла нет: {req.text}"
                    )
                    raise FileNotFoundError
                elif 'path/malformed_path/' in response['error_summary']:
                    logging.error(
                        f"Указан неправильный путь на сервере Dropbox: {path}"
                    )
                    raise FileNotFoundError
                logging.error(f"Проблема при загрузке файла: {req.text}")
                raise ConnectionAbortedError
            logging.debug('Файл загружен, сохраняем.')
            file.write(req.content)
    except FileNotFoundError:
        logging.error(f"Файл не найден: {file_path} \n\r"
                        f"Проверьте корректность пути и имени файла.")
        raise

    except PermissionError:
        logging.error(
            f"Ошибка доступа к файлу: {file_path} \n\r"
            f"Необходимы права на запись файла, либо некорректный путь."
        )
        raise

    print("Файл успешно загружен и сохранён.")
    return "Success"


def upload(tokens):
    """
    Uploads file to remote destination.
    """
    logging.debug(f"Source:{args.src}")
    file_path = check_local_path(args.src)
    logging.debug(f"Destination:{args.dst}")
    path = check_remote_URL(args.dst)
    logging.debug(f"Destination:{path}")

    headers = {'Authorization': f'Bearer {tokens["access_token"]}',
               'Content-Type': 'application/octet-stream',
               'Dropbox-API-Arg': json.dumps({
                   "autorename": True,
                   "mode": "add",
                   "mute": False,
                   "path": path,
                   "strict_conflict": False
               })
               }
    params = {}
    # TODO: provide hash to check if upload was correct
    # TODO: implement progress bar
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        logging.error(f"Файл не найден: {file_path} \n\r"
                        f"Проверьте корректность пути и имени файла.")
        raise
    except PermissionError:
        logging.error(f"Ошибка доступа к файлу: {file_path} \n\r"
                        f"Необходимы права на чтение файла.")
        raise
    print('Выгрузка файла на сервер Dropbox...')
    try:
        req = requests.post(
            CONTENT + '2/files/upload',
            headers=headers,
            params=params,
            data=data,
        )
    except (requests.exceptions.RequestException, ConnectionError) as error:
        logging.error(f"Проблема при подключении: {error}")
        raise

    logging.debug(f'Response status code: {req.status_code}')
    logging.debug(f'Response plaintext: {req.text}')
    if req.status_code != 200:
        if "did not match pattern" in req.text:
            raise ValueError(
                f"Ошибка выгрузки: {req.text}\n"
                f"Неправильный путь для файла на сервере: {args.dst}"
            )
        try:
            response = req.json()
        except ValueError:
            logging.error(f"Проблема при выгрузке файла: {req.text}")
            raise
        if 'path/conflict/file/' in response['error_summary']:
            raise FileExistsError(f"По заданному пути файл уже есть: {req.text}")
        elif 'path/malformed_path/' in response['error_summary']:
            raise FileNotFoundError(
                f"Указан неправильный путь на сервере Dropbox: {path}"
            )
        raise ConnectionAbortedError(f"Проблема при выгрузке файла: {req.text}")
    print("Файл успешно выгружен")
    return "Success"


def main():
    logging.debug(args)
    try:
        tokens = check_tokens()
        if args.load == 'up':
            result = upload(tokens)
        elif args.load == 'down':
            result = download(tokens)
        logging.info(result)
    except (PermissionError,
            FileNotFoundError,
            ValueError,
            FileExistsError,
            ConnectionAbortedError,
            requests.exceptions.RequestException,
            ConnectionError,
            IsADirectoryError,
            ConnectionRefusedError,
            ) as error:
        message = f'Ошибка: {error}'
        logging.error(message)
    print('выход')


if __name__ == '__main__':
    main()
