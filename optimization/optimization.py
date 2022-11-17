import multiprocessing
import time
#from collections import defaultdict
from datetime import datetime
from itertools import repeat
import networkx as nx
from networkx.algorithms.isomorphism import DiGraphMatcher

from integration.integration import Integration


class Optimization(Integration):
    priority_treshold = 80

    @classmethod
    def pre_optimization(cls, level, alerts, max_procs):
        # For your implementation
        level
        max_procs
        return alerts

    @classmethod
    def optimization(cls, spread_graphs: list, level: int, max_procs: int, alerts: dict, events: list):
        return spread_graphs, []

    @classmethod
    def post_optimization(cls, ukc: list, max_procs, level: int = 1):
        ukc = add_reflexive_edges(ukc)
        # Every time:
        start = time.time()
        ukc = prune_identical_ukc_scenarios(ukc, max_procs)
        print(f'{datetime.now()}: pruned identical scenarios in {time.time() - start} seconds: {len(ukc)} '
              f'remaining')

        if level:
            start = time.time()
            ukc = prune_irrelevant_ukc_scenarios(ukc)
            print(f'{datetime.now()}: pruned irrelevant scenarios in {time.time() - start} seconds: '
                  f'{len(ukc)} remaining')
        if level == 2:
            pass
        return ukc


def find_event_connection(events: list, src: list, dst: list, earlier, later) -> dict or None:
    # simple implementation
    for event in events:
        if not event['attackers'] == src:
            continue
        if not event['victims'] == dst:
            continue
        if earlier < event['ts'] < later:
            return event
    return None


# Following are Optimization functions
def deduplicate_ukc(params):
    (i, UKC_scenarios, duplicates) = params
    ukc_A = UKC_scenarios[i]

    if duplicates[i]:
        return

    for j, ukc_B in enumerate(UKC_scenarios):
        if i == j or duplicates[j]:
            continue

        matcher = DiGraphMatcher(ukc_A, ukc_B,
                                 node_match=lambda sup, sub: sup['ips'] == {'Internet'} or sup['ips'].issuperset
                                 (sub['ips']),
                                 edge_match=lambda sup, sub: sub['stages'] == {'Unknown infection start'} or sup
                                 ['stages'].issuperset(sub['stages']))
        if matcher.subgraph_is_isomorphic():
            duplicates[j] = True


def prune_identical_ukc_scenarios(ukc_scenarios, max_procs):
    """
    Removes all duplicate scenarios. A duplicate is defined as an ukc that carries the same or less information as
    another ukc. Therefore, an ukc, say `B`, duplicates another ukc, say `A` iff: `B` is an isomorphic sub-graph of
    `A` and all edges and nodes carry the same or fewer annotations.

        Example:
        ukc A: {'1.1.1.1', '1.1.1.2'} --Deliver--> {'5.5.5.5'}
        ukc B: {'1.1.1.1'}            --Deliver--> {'5.5.5.5'}
        Then ukc B is a duplicate of ukc A
    """
    ukc_scenarios = set(ukc_scenarios)
    ukc_scenarios = list(ukc_scenarios)

    print('{}: allocating manager + array'.format(datetime.now()))
    with multiprocessing.Manager() as mgr:
        pool = multiprocessing.Pool(processes=max_procs)
        duplicates = mgr.list([False] * len(ukc_scenarios))

        idx = 0
        total = len(ukc_scenarios)
        print('{}: starting pool loop'.format(datetime.now()))
        for _ in pool.imap_unordered(deduplicate_ukc,
                                     zip(range(len(ukc_scenarios)), repeat(ukc_scenarios), repeat(duplicates)),
                                     chunksize=100):
            idx += 1
            if idx % 100 == 0:
                print('{}: {}/{} ({}%)'.format(datetime.now(), idx, total, idx / total * 100))

        pool.close()

        result = [ukc for i, ukc in enumerate(ukc_scenarios) if not duplicates[i]]

    return result


def prune_irrelevant_ukc_scenarios(ukc_scenarios):
    """
        Removes all ukc scenarios that only does not consist of two edges with stage labels.
    """
    relevant = []
    for UKC in ukc_scenarios:
        # longest = dag_longest_path(UKC)
        # if len(longest) <= 2:  # and ukc.node[longest[0]]['ips'] == set(['Internet']):
        #     continue
        c = 0
        for src, dst, data in UKC.edges(data=True):
            if set(str(data['stages'])) & {'D1', 'D2', 'C', 'L', 'E', 'O', 'S', 'H', 'R'}:
                c += 1
        if c >= 2:
            relevant.append(UKC)
    return relevant


def add_reflexive_edges(ukc_scenarios) -> list:
    # for every ukc scenario
    new_scenarios = []
    for ukc in ukc_scenarios:
        new_scenarios.append(add_reflexive(ukc))

    return new_scenarios


def add_reflexive(ukc):
    for src, dst, data in ukc.edges(data=True):
        if data['stages'] == {'H'} and dst != src:
            ukc.add_edge(src, src)
            ukc.edges[src, src]['stages'] = {'H'}
            for nsrc, ndst, nstages in ukc.out_edges(dst, data=True):
                if nstages == 'H':
                    continue
                ukc.add_edge(src, ndst)
                ukc.edges[src, ndst]['stages'] = nstages['stages']
            ukc.remove_node(dst)
            return add_reflexive(ukc)
    return ukc


def merge_graphs(ukc_a, ukc_b, edge: tuple[str, str, dict], src: set, dst: set):
    ukc = nx.compose(ukc_a, ukc_b)
    ukc.add_edge(edge[0], edge[1])
    ukc.edges[edge[0], edge[1]]['stages'] = set(edge[2]['stages'])
    ukc.edges[edge[0], edge[1]]['source'] = src
    ukc.edges[edge[0], edge[1]]['target'] = dst
    return ukc
