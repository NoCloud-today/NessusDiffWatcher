import configparser
import json

import requests
import shlex
import os
import subprocess
import sys
from datetime import datetime


def is_debug_mode() -> bool:
    return '--debug' in sys.argv


def check_config_variable(value, variable_name):
    if not value:
        sys.stderr.write(f"\033[mConfiguration error: Check the environment variables: {variable_name}.\033[0m\n")
        sys.stderr.flush()
        sys.exit(1)


def get_config() -> tuple:
    config = configparser.ConfigParser()

    if not os.path.exists("settings.ini"):
        sys.stderr.write("\033[mError: The configuration file 'settings.ini' does not exist.\033[0m\n")
        sys.stderr.flush()
        sys.exit(1)

    try:
        config.read("settings.ini")
        bash_command_conf = config["NOTIFICATION"]["NOTIFICATION_CMD"]
        message_template_conf = config["NOTIFICATION"]["NOTIFICATION_TEMPLATE"]
        access_key_conf = config['NESSUS']['ACCESS_KEY']
        secret_key_conf = config['NESSUS']['SECRET_KEY']

        check_config_variable(bash_command_conf, "NOTIFICATION_CMD")
        check_config_variable(message_template_conf, "NOTIFICATION_TEMPLATE")
        check_config_variable(access_key_conf, "ACCESS_KEY")
        check_config_variable(secret_key_conf, "SECRET_KEY")

        names_scans_conf = config['SCANS'].values()
        filtered_scan_names = [name for name in names_scans_conf if name]

    except KeyError as e:
        sys.stderr.write(f"\033[mConfiguration error: Missing environment variable: {e}.\033[0m\n")
        sys.stderr.flush()
        sys.exit(1)

    return (
        bash_command_conf,
        message_template_conf,
        access_key_conf,
        secret_key_conf,
        filtered_scan_names
    )


def get_scans() -> dict:
    headers = {
        'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
    }
    url = 'https://localhost:8834/scans'

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"\033[mError receiving scans: {e}.\033[0m\n")
        sys.stderr.flush()
        exit(1)

    return response.json()['scans']


def get_info_scan(id_scan: str) -> dict:
    headers = {
        'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
    }
    url = f'https://localhost:8834/scans/{id_scan}'

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        with open(f"response_scan_{id_scan}.json", "w") as file:
            json.dump(response.json(), file, indent=8)

    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"\033[mError receiving scans: {e}.\033[0m\n")
        sys.stderr.flush()
        exit(1)

    return response.json()


if __name__ == '__main__':
    bash, message_temp, access_key, secret_key, names_scans = get_config()

    scans = get_scans()
    get_info_scan('42')
    for scan in scans:
        if scan['name'] in names_scans:
            get_info_scan(scan['id'])
            print(scan['name'], ' ', scan['id'])