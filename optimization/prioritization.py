import ipaddress as ip
from collections import defaultdict


class Prioritization:
    borderline_infected: int = 4

    @classmethod
    def prioritization(cls, ukc, max_procs: int, zones: dict, meta: dict, treshold: int = 0):
        for scenario in ukc:
            meta[scenario.name].update(cls.calculate_priority(scenario=scenario, zones=zones))
        if treshold:
            output = []
            for scenario in ukc:
                if meta[scenario.name] >= treshold:
                    output.append(treshold)
            ukc = output
        print(prio_stats(meta=meta, treshold=40))
        return ukc, meta

    @classmethod
    def calculate_priority(cls, scenario, zones) -> dict:
        nz_stages = {zone: set() for zone in zones}
        nz_infected = {zone: set() for zone in zones}
        nz_nodes = {zone: set() for zone in zones}

        # Prepare some information
        for node, data in scenario.nodes(data=True):
            if data['ips'] == set():
                continue
            zone = get_network_zone(list(data['ips'])[0], zones)
            if zone == 'Internet':
                continue
            nz_nodes[zone].add(node)
            for src, dst, stages in scenario.out_edges(node, data=True):
                nz_stages[zone] = nz_stages[zone].union(stages['stages'])
            nz_infected[zone] = nz_infected[zone].union(data['ips'])

        for nz in zones:
            # Special Case: On objective
            if 'O' in nz_stages[nz] or 'E' in nz_stages[nz] or zones[nz]['severity'] == 0:
                return {
                    'score': 100,
                    'type': f'Compromise - {nz_stages[nz]} detected',
                    'zone': nz
                }

        length_prio = cls.compute_length_score(ukc=scenario)
        asset_prio = cls.compute_asset_score(zones=zones, nz_stages=nz_stages)
        authenticity_prio = cls.compute_authenticity_score(ukc=scenario, nz_stages=nz_stages)
        infected_prio = cls.compute_infection_score(zones=zones, infections=nz_infected)
        score = cls.weight_length(length_prio['Score']) + cls.weight_asset(asset_prio['Score']) + \
                cls.weight_authenticity(authenticity_prio['Score']) + cls.weight_infection(infected_prio['Score'])

        return {'score': int(min(score, 99)),
                'Totals': {
                    'length_prio': length_prio['Score'],
                    'asset_prio': asset_prio['Score'],
                    'authenticity_prio': authenticity_prio['Score'],
                    'infected_prio': infected_prio['Score']
                },
                'Weighted': {
                    'length_prio': cls.weight_length(length_prio['Score']),
                    'asset_prio': cls.weight_asset(asset_prio['Score']),
                    'authenticity_prio': cls.weight_authenticity(authenticity_prio['Score']),
                    'infected_prio': cls.weight_infection(infected_prio['Score'])
                },
                'length_prio': length_prio['Details'],
                'asset_prio': asset_prio['Details'],
                'authenticity_prio': authenticity_prio['Details'],
                'infected_prio': infected_prio['Details']
                }

    @staticmethod
    def weight_length(x):
        return max(0.25 * x, 0)

    @staticmethod
    def weight_asset(x):
        return max(0.012 * x**2 - 0.21 * x, 0)

    @staticmethod
    def weight_infection(x):
        return max(0.25 * x, 0)

    @staticmethod
    def weight_authenticity(x):
        return max(1.8 * x - 81, 0)

    @staticmethod
    def compute_length_score(ukc) -> dict:
        x = ukc.number_of_nodes()
        score = int(0.05 * x**3 - 1.25 * x**2 + 11.2 * x)
        return {'Score': score, 'Details': f'Function  = {score}'}

    @staticmethod
    def compute_asset_score(zones, nz_stages) -> dict:
        network_stages: set = {'L', 'S', 'P', 'H', 'C'}
        asset_network_stages: set = {'L', 'H', 'C'}
        nz_meta = {zone: {} for zone in zones}
        high_score = 0

        for nz in zones:
            # Assigning variables for Case: dta = 1
            if zones[nz]['severity'] == 1:
                zone_intervall = 0.2
                asset_risk = len(nz_stages[nz] & asset_network_stages) * 20
            # Assigning variables Case: Default case
            else:
                zone_intervall = 0.4
                asset_risk = len(nz_stages[nz] & network_stages) * 20
            # Calculations
            zone_risk = int(80 / zones[nz]['severity']) * min(1, len(nz_stages[nz]))  # 80 40 20 10
            nz_meta[nz]['score'] = min(int(zone_risk + zone_intervall * asset_risk), 100)

            if nz_meta[nz]['score'] > high_score:
                high_score = nz_meta[nz]['score']

        return {'Score': high_score, 'Details': nz_meta}

    @staticmethod
    def compute_authenticity_score(ukc, nz_stages) -> dict:
        authenticity_score = {'Details': {}, 'Score': 0}
        # infection_transitions = {'L', 'P', 'D1'}
        breach_subscore, start_subscore, i_score, h_score = 0, 100, 0, 0
        breached_nz = 0
        for nz in nz_stages:
            if nz_stages[nz]:
                breached_nz += 1

        if breached_nz - 1:
            for nz in nz_stages:
                # assess breach over P, S stages
                if 'P' in nz_stages[nz]:
                    breach_subscore += 1
                if 'S' in nz_stages[nz]:
                    breach_subscore += 1
            if breach_subscore:
                breach_subscore = (breached_nz - 1) * 2 / breach_subscore
        else:
            breach_subscore = 0.5

        for src, dst, data in ukc.edges(data=True):
            # assess infected have host alerts
            if {'L', 'P', 'D1'} & data['stages']:
                i_score += 1
                for nsrc, ndst, ndata in ukc.out_edges(dst, data=True):
                    if {'H'} & ndata['stages']:
                        h_score += 1
                        break

            # assess (if possible) distance to start
            # look for start if unknown infection start
            if data['stages'] == {'unknown_infection_start'}:
                start_subscore -= 50
        # number of network zones crossed
        if breached_nz <= 1:
            start_subscore -= 50
        infection_subscore = (h_score / i_score) if h_score else 0

        authenticity_score['Score'] = int(0.33 * start_subscore + 33 * infection_subscore + 33 * breach_subscore)
        authenticity_score['Details'] = {
            'start': start_subscore,
            'infection_subscore': infection_subscore,
            'breach_subscore': breach_subscore
        }
        return authenticity_score

    @staticmethod
    def compute_infection_score(zones, infections) -> dict:
        borderline_default = 4
        borderline_network, compromised = 40, 0
        quantity_score = 0
        infection_score = {'Details': {}, 'Score': 0}
        for nz in zones:
            nz_borderline = zones[nz]['borderline'] if 'borderline' in zones[nz] else borderline_default
            infection_score['Details'][nz] = int(min(len(infections[nz]) / nz_borderline, 1) * 100)
            quantity_score = int(max(infection_score['Details'][nz], quantity_score))
            compromised += len(infections[nz])

        infection_score['Details']['Network'] = int(min(compromised / borderline_network, 1) * 100)
        infection_score['Score'] = max(quantity_score, infection_score['Details']['Network'])
        infection_score['Details']['Score'] = infection_score['Score']
        return infection_score


def get_network_zone(ip_a, networks) -> str:
    if ip_a == 'Internet':
        return 'Internet'
    for name, networks in networks.items():
        if ip.ip_address(ip_a) in ip.ip_network(networks['subnet']):
            return name
    return 'Internet'


def prio_stats(meta, treshold) -> defaultdict:
    stats = defaultdict(int)
    prune = 0
    for ukc in meta:
        stats[meta[ukc]['score']] += 1
        if treshold:
            if treshold >= meta[ukc]['score']:
                prune += 1

    print("Would prune: " + str(prune))
    return stats
