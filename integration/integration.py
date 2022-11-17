"""
 Integration for Liva
"""
import json
import logging
import uuid
import ipaddress as ip

import connection_helper.client as es


def valid_ip(ips: str) -> bool:
    octets = ips.split('.')
    if octets == "Null" or len(octets) != 4:
        return False

    for octet in octets:
        if octet.startswith("0"):
            return False
        if not octet.isdecimal():
            return False
        if not 0 <= int(octet) <= 255:
            return False
    return True


def generate_uuid():
    return str(uuid.uuid4())


class Integration:
    apt_preconditions = {
        'R': set(),
        'D1': {'R'},
        'D2': {'D1', 'H'},
        'C': {'D1', 'D2', 'C', 'L', 'H'},
        'L': {'D1', 'D2', 'C', 'L', 'E', 'O', 'S', 'H'},
        'P': {'D1', 'D2', 'C', 'L', 'H'},
        'S': {'D1', 'D2', 'C', 'L', 'P', 'H'},
        'E': {'D1', 'D2', 'C', 'L', 'E', 'O', 'H'},
        'O': {'D1', 'D2', 'C', 'L', 'E', 'O', 'H'},
        'H': {'L', 'C', 'D1', 'D2', 'H'}
    }

    # lookup table for APT stages to get possible post-condition stages
    apt_postconditions = {
        'R': {'D1'},
        'D1': {'D2', 'C', 'E', 'L', 'P', 'S', 'O', 'H'},
        'D2': {'C', 'E', 'L', 'P', 'S', 'O', 'H'},
        'C': {'C', 'E', 'L', 'P', 'S', 'O', 'H'},
        'L': {'C', 'E', 'L', 'P', 'S', 'O', 'H'},
        'P': {'S'},
        'S': {'L'},
        'H': {'C', 'E', 'L', 'P', 'S', 'O', 'H', 'D2'},
        'E': {'E', 'O', 'L'},
        'O': {'E', 'O', 'L'}
    }

    def __init__(self, argv, config_path: str = "example-config.json"):
        # Configuration
        self.config = self.parse_config(config_path)
        self.cache = self.config.get('cache') if self.config.get('cache') else ""
        max_procs = self.config.get('max_procs')
        if argv.gcalgorithm:
            self.event_cache = self.config.get('event_cache')
        if max_procs:
            self.max_procs = max_procs if max_procs else 1
            logging.info(f'Max Procs set to {max_procs}')
        if not self.config.get('zones'):
            exit('Network zone configuration is required.')

        self.zones = dict()
        for name, details in self.config['zones'].items():
            networks = []
            for ip_range in details['subnet'].split(','):
                networks.append(ip.ip_network(ip_range))
            self.zones[name] = networks

        if not self.config.get('cache'):
            # Elastic Init
            if 'elastic' in self.config:
                cfg = self.config.get('elastic')
                self.elastic = es.Client(host=cfg['addr'], port=cfg['port'], credentials=cfg['credentials'], indices=cfg['indices'])

    def integrate(self) -> None:
        if self.event:
            with open(self.cache) as f:
                alerts = json.load(f)
            with open(self.event_cache) as f:
                events = json.load(f)
            self.cache = "tmp_cache.json"
            with open("tmp_cache.json", 'w') as f:
                json.dump(fp=f, obj=events + alerts)
            logging.info(f"Created {self.cache} as cache")
        return None

    def get_events(self):
        with open(self.event_cache) as f:
            return json.load(f)

    @staticmethod
    def parse_config(config_path: str = "config_standard.json") -> dict:
        with open(config_path) as f:
            return json.load(f)

    @staticmethod
    def normalize_alert(alert) -> dict:
        """Returns dictionary defined by the alert interface
        :param alert:
        :return: Alert Dictionary
        """
        if not alert:
            raise KeyError
        if not isinstance(alert['attackers'], list):
            alert['attackers'] = [alert['attackers']]
        if type(alert['victims']) is not list:
            alert['victims'] = [alert['victims']]

        return {
            'uid': generate_uuid(),
            'ts': alert['ts'],  # timestamp
            'type': alert['type'],  # No use
            # 'message': alert['zeek']['notice']['msg'],  # probably: 127.0.0.1 -> 127.0.0.2; not used anymore
            'alert_ids': alert['alert_ids'],  # used: get by uid, list, are ids
            'attackers': alert['attackers'],  # src ip
            'victims': alert['victims']  # dest ip
        }

    def get_alerts(self, earliest_date: str, latest_date: str, date_format: str, cache: str):
        """
        Wrapper for Database Request
        """
        if cache:
            with open(cache) as f:
                return json.load(f)
        else:
            self.config['elasticsearch']['indices']

    def get_alert_details(self, ma) -> tuple[str, str]:
        self
        return ma['ts'], ma['ts']
