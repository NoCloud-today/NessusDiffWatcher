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
        access_key_conf = config['NESSUS']['ACCESS_KEY']
        secret_key_conf = config['NESSUS']['SECRET_KEY']

        check_config_variable(bash_command_conf, "NOTIFICATION_CMD")
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

    if is_debug_mode():
        sys.stdout.write(f"\033[92mThe scans have been sent successfully.\033[0m\n")
        sys.stdout.flush()

    return response.json()['scans']


def get_info_scan(id_scan: str) -> dict:
    headers = {
        'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
    }
    url = f'https://localhost:8834/scans/{id_scan}'

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"\033[mError receiving scans: {e}.\033[0m\n")
        sys.stderr.flush()
        exit(1)

    if is_debug_mode():
        sys.stdout.write(f"\033[92mThe scan \"{response.json()['info']['name']}\" has been sent successfully.\033[0m\n")
        sys.stdout.flush()

    return response.json()


def count_total_dict(scan_count: dict):
    severity_plugs = {
        'Info': [],
        'Low': [],
        'Medium': [],
        'High': [],
        'Critical': []
    }

    if isinstance(scan_count, dict):
        items = scan_count.values()
    elif isinstance(scan_count, list):
        items = scan_count
    else:
        raise ValueError("Input should be a list or a dictionary")

    for vuln in items:
        severity_name = {
            0: 'Info',
            1: 'Low',
            2: 'Medium',
            3: 'High',
            4: 'Critical'
        }.get(vuln.get('severity', 'Unknown'))

        if severity_name in severity_plugs:
            severity_plugs[severity_name].append(vuln.get('plugin_name'))

    return severity_plugs


def parse_one_scan(scan_vuln: dict) -> dict:
    scan_vulnerabilities = {}
    for vul in scan_vuln:
        scan_vulnerabilities[vul['plugin_name']] = {
            'count': vul['count'],
            'severity': vul['severity']
        }

    return scan_vulnerabilities


def count_total_list(scan_count: list[dict]):
    severity_plugs = {
        'Info': [],
        'Low': [],
        'Medium': [],
        'High': [],
        'Critical': []
    }

    for vuln in scan_count:
        for key, value in vuln.items():
            severity_name = {
                0: 'Info',
                1: 'Low',
                2: 'Medium',
                3: 'High',
                4: 'Critical'
            }.get(value.get('severity', 'Unknown'))

            if severity_name in severity_plugs:
                severity_plugs[severity_name].append(key)

    return severity_plugs


def parse_two_scans(scan_vuln_new: dict, object_id: str) -> (dict, dict):
    with open(f"{directory_path}/scan_{object_id}.json", 'r') as file_prev:
        scan_vul_prev = json.load(file_prev)

    if int(scan_vul_prev['info']['scanner_end']) == int(scan_vuln_new['info']['scanner_end']):
        return "There is no new report", ''

    if scan_vul_prev['vulnerabilities'] == scan_vuln_new['vulnerabilities']:
        return "No differences with the previous", ''

    prev_dict = parse_one_scan(scan_vul_prev['vulnerabilities'])
    new_dict = parse_one_scan(scan_vuln_new['vulnerabilities'])

    keys_closed = []
    keys_new_open = []
    keys_remove = []

    for key, value in new_dict.items():
        if key in prev_dict:
            if value['count'] < prev_dict[key]['count']:
                keys_closed.append({key: prev_dict[key]['count'] - value['count']})
            elif value['count'] > prev_dict[key]['count']:
                keys_new_open.append({key: value['count'] - prev_dict[key]['count']})
            keys_remove.append(key)
        else:
            keys_new_open.append({key: new_dict[key]})

    for key in keys_remove:
        del prev_dict[key]

    for key, value in prev_dict.items():
        keys_closed.append({key: value})

    return count_total_list(keys_new_open), count_total_list(keys_closed)


def update_template(message_template_up: str, message_send, curr_time: str) -> str:
    """
    Updates a notification message template with specific details.

    Args:
        message_template_up (str): The original message template.
        message_send (str): The message content to insert into the template.
        curr_time (str): The timestamp to insert into the template.

    Returns:
        str: The updated message template.
    """
    message_content = message_template_up.replace('{MESSAGE}', message_send)
    message_content = message_content.replace('{creationTime}', curr_time)

    return message_content


def send_message(bash_cmd_line: str, message_to_deliver: str, name_scan: str) -> bool:
    message_to_deliver = shlex.quote(message_to_deliver)
    message_to_deliver = message_to_deliver[1:-1]
    html_message_to_deliver = '<br/>'.join(message_to_deliver.splitlines())

    bash_cmd_line = bash_cmd_line.replace("{MESSAGE}", message_to_deliver)
    bash_cmd_line = bash_cmd_line.replace("{HTML_MESSAGE}", html_message_to_deliver)

    if is_debug_mode():
        sys.stdout.write(f"\033[33mCMD: {bash_cmd_line}\033[0m\n")

    process = subprocess.run(
        bash_cmd_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    if process.returncode != 0:
        sys.stderr.write(
            f"\033[mScan \"{name_scan}\" was not sent successfully.\n{process.stderr}\033[0m\n"
        )
        sys.stderr.flush()
        return False

    sys.stdout.write(
        f"\033[92mThe scan \"{name_scan}\" has been sent successfully.\033[0m\n"
    )
    sys.stdout.flush()
    return True


if __name__ == '__main__':
    current_time = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    sys.stdout.write(f"Time: {current_time}\n")
    sys.stdout.flush()

    bash_cmd, access_key, secret_key, names_scans = get_config()

    directory_path = './reports'
    os.makedirs(directory_path, exist_ok=True)

    scans = get_scans()
    for scan in scans:
        if scan['name'] in names_scans:
            info_scan = get_info_scan(scan['id'])

            if info_scan['info']['status'] != 'completed':
                time_ = datetime.fromtimestamp(info_scan['info']['scanner_start']).strftime("%Y-%m-%d %H:%M:%S")
                message_to = f"Scan *{scan['name']}* ({time_}): {info_scan['info']['status']}"
                send_message(bash_cmd, message_to, scan['name'])
                continue

            time_ = datetime.fromtimestamp(info_scan['info']['scanner_end']).strftime("%Y-%m-%d %H:%M:%S")
            if not os.path.exists(f"{directory_path}/scan_{scan['id']}.json"):
                total_names = count_total_dict(info_scan['vulnerabilities'])
                combined_output = ""
                for key, value in total_names.items():
                    combined_line = f"\t{key}: {len(value)}"
                    if value:
                        combined_line += '\n\t' + '; '.join(map(str, value))
                    combined_output += combined_line + "\n"
                message_to = f'Scan *{scan["name"]}* ({time_})\nThis is first scan\nVulnerabilities:\n{combined_output}'

            else:
                total_names_new, total_names_closed = parse_two_scans(info_scan, scan['id'])
                if isinstance(total_names_new, str):
                    message_to = f'Scan *{scan["name"]}* ({time_})\n{total_names_new}'
                else:
                    combined_output_new = ""
                    combined_output_closed = ""
                    for key, value in total_names_new.items():
                        combined_line = f"\t{key}: {len(value)}"
                        if value:
                            combined_line += '\n\t' + '; '.join(map(str, value))
                        combined_output_new += combined_line + "\n"
                    for key, value in total_names_closed.items():
                        combined_line = f"\t{key}: {len(value)}"
                        if value:
                            combined_line += '\n\t' + '; '.join(map(str, value))
                        combined_output_closed += combined_line + "\n"

                    message_to = (f'Scan *{scan["name"]}* ({time_})\nNew vulnerabilities:\n{combined_output_new}\n'
                                  f'Closed:\n{combined_output_closed}')

            send_message(bash_cmd, message_to, scan['name'])
            with open(f"{directory_path}/scan_{scan['id']}.json", "w") as file:
                json.dump(info_scan, file, indent=8)
