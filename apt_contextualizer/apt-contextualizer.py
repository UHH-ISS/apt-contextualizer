import argparse
import logging
from typing import Any
from collections import defaultdict
from datetime import datetime
import ipaddress as ip
import json
import networkx as nx
from networkx.readwrite import json_graph
from itertools import repeat
import multiprocessing
from networkx.algorithms.simple_paths import all_simple_paths
from networkx.classes.function import is_empty
import os
from os import mkdir
import pickle
import textwrap
import time
import uuid
import warnings

from integration.integration import Integration
from optimization.optimization import Optimization
from optimization.prioritization import Prioritization


def store_to_file(obj, file_name, out_folder='out'):
    file_name += '.pickle'
    with open(f'{out_folder}/{file_name}', 'wb') as handle:  # path.join(out_folder + file_name)
        pickle.dump(obj, handle, protocol=pickle.HIGHEST_PROTOCOL)


def restore_from_file(file_name, folder='out'):
    file_name += '.pickle'
    with open(f'{folder}/{file_name}', 'rb') as handle:
        obj = pickle.load(handle)
    return obj


def graph_to_json(dg: nx.DiGraph):
    return json_graph.node_link_data(G=dg)


class AptContextualizer(Integration):
    # lookup table for APT stages to get possible pre-condition stages

    # set class variables for certain stages to avoid constant recreation
    movement_stages = {'L', 'P'}
    internal_stages = {'S'}
    external_stages = {'D2', 'C', 'E'}
    drop_stages = {'D1'}
    recon_stages = {'R'}
    host_stages = {'H', 'O'}

    outgoing_stages = {'D2', 'C', 'E'}
    incoming_stages = {'R', 'D1'}
    same_zone_stages = {'L', 'S'}
    diff_zone_stages = {'L', 'P', 'S'}
    infection_movement_stages = {'L', 'P', 'D1', 'H'}
    static_stages = {'H', 'O'}

    ukc_start_stages = {'R', 'D1'}
    ukc_unknown_start_stage = {'Unknown infection start'}

    def __init__(self, argv):
        logging.basicConfig(filename='apt-contextualizer.log', encoding='utf-8', level=logging.INFO)
        super(AptContextualizer, self).__init__(config_path=argv.config, argv=argv)
        self.event = argv.event
        self.gca = argv.gcalgorithm
        self.opt_level = argv.optimization
        self.mapping = argv.mapping
        self.obj = argv.objective
        self.prio = argv.prioritization
        if self.prio:  # Requirements for priorization
            self.obj = True
            self.mapping = True
        if self.obj:
            AptContextualizer.static_stages = {'H'}

    @staticmethod
    def draw_spread_tree(tree, file_name, out_folder='out/trees', compact=True) -> None:
        """
        Draws a infection spread tree `tree` and outputs a file with the wanted `file_format` and `file_name` to the
        `out_folder`.
        """
        out_folder = f'{path}{out_folder}'
        file_name = file_name + '.'
        file_name = file_name.replace('>', '')
        if not os.path.isdir(f'{path}out'):
            mkdir(f'{path}out')
        if not os.path.isdir(out_folder):
            mkdir(out_folder)
        tree = tree.copy()  # necassary, because pass by reference would change for the following flow

        for u, v, data in tree.edges(data=True):
            stages = ', '.join(data['stages'])
            if compact:
                data['label'] = stages
            else:
                if not AptContextualizer.get_recon_stages(data['stages']) and not AptContextualizer.get_drop_stages(
                        data['stages']) or len(data['source']) < 5:
                    source = '\n'.join(textwrap.wrap(str(data['source']), width=30))
                else:
                    source = 'Internet'
                if not AptContextualizer.get_external_action_stages(data['stages']) or len(data['target']) < 5:
                    target = '\n'.join(textwrap.wrap(str(data['target']), width=30))
                else:
                    target = 'Internet'
                data['label'] = 'stages: {}\nsource: {}\ntarget: {}'.format(stages, source, target)

        # Hot Fix Style for GraphML
        for node, data in tree.nodes(data=True):
            data['label'] = ''
            data['alerts'] = ''
            del data['alerts']

        for n0, n1, data in tree.edges(data=True):
            data['stages'] = ''
            data['source'] = ''
            data['target'] = ''
            del data['source']
            del data['stages']
            del data['target']

        nx.write_graphml_xml(tree, out_folder + '/' + file_name + "graphml", prettyprint=True)

    @staticmethod
    def persist_ukc(ukc, file_name, meta, out_folder='out/ukc'):
        """
        Persists the `ukc` tree and outputs a file with the wanted `file_format` and `file_name` to the `out_folder`.
        """
        if not os.path.isdir(f'{path}{out_folder}'):
            mkdir(f'{path}{out_folder}')
        # file_name = f'{path}{out_folder}/{file_name}'

        # Stringify data to be able to save as graphml
        # 'label' is chosen because this is also used while drawing
        for node, data in ukc.nodes(data=True):
            data['label'] = str(data['ips'])
            del data['ips']

        for src, dst, data in ukc.edges(data=True):
            data['label'] = str(data['stages'])
            del data['stages']

        if not os.path.isdir(f'{path}{out_folder}/json'):
            mkdir(f'{path}{out_folder}/json')
        output = graph_to_json(ukc)
        output['meta'] = meta
        with open(f'{path}{out_folder}/json/{file_name}.json', 'w') as f:
            json.dump(obj=output, fp=f)

        nx.readwrite.graphml.write_graphml(ukc, f'{path}{out_folder}/{file_name}.graphml', prettyprint=True)

    @staticmethod
    def is_incoming(direction):
        """
            Predicate to determine if a network direction is incoming from the internet to an internal network zone.
        """
        return 'Internet->' in direction

    @staticmethod
    def is_outgoing(direction):
        """
            Predicate to determine if a network direction is outgoing from an internal network zone to the internet.
        """
        return '->Internet' in direction

    @staticmethod
    def rand_uid():
        """
            Returns a new, random uuid v4.
        """
        return str(uuid.uuid4())

    @staticmethod
    def serialize_set(input_set):
        """Serializes a python set() object as string. can be deserialized with `self. deserialize_set()`"""
        return json.dumps(sorted(input_set))

    @staticmethod
    def deserialize_set(input_str):
        """Deserializes a str to a python set() object (must have been serialized with `self. serialize_set()`"""
        return set(json.loads(input_str))

    @staticmethod
    def is_static(direction) -> bool:
        return '->host' in direction

    @staticmethod
    def get_potential_apt_stages(direction):
        """Returns APT Stages
        :param direction:

        :return:
        """
        # determine Internet incoming/outgoing
        if AptContextualizer.is_static(direction):
            return AptContextualizer.static_stages
        if AptContextualizer.is_outgoing(direction):
            return AptContextualizer.outgoing_stages
        if AptContextualizer.is_incoming(direction):
            return AptContextualizer.incoming_stages

        # else: internal
        source_network, target_network = direction.split('->')
        if source_network == target_network:
            return AptContextualizer.same_zone_stages
        return AptContextualizer.diff_zone_stages

    @staticmethod
    def is_valid_assignment(stages, direction):
        """Predicate to determine if the stages are valid for the given direction
        #Works (Validation)
        """
        # no movement
        if AptContextualizer.is_static(direction):
            if 'O' in stages:
                return True
            return stages & AptContextualizer.static_stages
        # outgoing to Internet
        if AptContextualizer.is_outgoing(direction):
            return stages & AptContextualizer.outgoing_stages
        # incoming from Internet
        if AptContextualizer.is_incoming(direction):
            return stages & AptContextualizer.incoming_stages

        source_network, target_network = direction.split('->')
        # purely internal: same zone
        if source_network == target_network:
            return stages & AptContextualizer.same_zone_stages
        # purely internal: diff zone
        return stages & AptContextualizer.diff_zone_stages

    @staticmethod
    def get_movement_stages(stages):
        """
        Returns all movement stages that are contained in the given stages, if any. Returns an empty set otherwise.
        """
        return stages & AptContextualizer.movement_stages

    @staticmethod
    def get_internal_action_stages(stages):
        """
        Returns all internal action stages that are contained in the given stages, if any. Returns an empty set
        otherwise.
        """
        return stages & AptContextualizer.internal_stages

    @staticmethod
    def get_external_action_stages(stages):
        """
        Returns all external action stages that are contained in the given stages, if any. Returns an empty set
        otherwise.
        """
        return stages & AptContextualizer.external_stages

    @staticmethod
    def get_drop_stages(stages):
        """
        Returns the drop stage if present in the given stages. Returns an empty set otherwise.
        """
        return stages & AptContextualizer.drop_stages

    @staticmethod
    def get_recon_stages(stages):
        """
        Returns the recon stage if present in the given stages. Returns an empty set otherwise.
        """
        return stages & AptContextualizer.recon_stages

    def get_directions(self, meta_alert) -> defaultdict[Any, dict]:
        """
        Returns all possible directions for the given meta-alert as dictionary. A direction points to the involved
        `source` and `target` nodes.
        #Works (
        :return:
        """
        directions = defaultdict(dict)

        # Host Case; all ips should be in same network zone
        if meta_alert['attackers'] == meta_alert['victims'] and meta_alert['victims']:
            direction = self.get_network_zone(meta_alert['victims'][0]) + '->' + 'host'
            directions[direction]['source'] = set(meta_alert['attackers'])
            directions[direction]['target'] = set(meta_alert['victims'])
            return directions

        for src_ip in meta_alert['attackers']:
            for dst_ip in meta_alert['victims']:
                # host case; no movement
                if src_ip == dst_ip:
                    direction = self.get_network_zone(src_ip) + '->' + 'host'
                else:
                    direction = self.get_network_zone(src_ip) + '->' + self.get_network_zone(dst_ip)
                if direction != 'Internet->Internet':
                    if not directions[direction].get('source', None):
                        directions[direction]['source'] = set()
                    if not directions[direction].get('target', None):
                        directions[direction]['target'] = set()
                    directions[direction]['source'].add(src_ip)
                    directions[direction]['target'].add(dst_ip)
        return directions

    def get_network_zone(self, addr) -> str:
        """
            Returns the network zone name that was configured in the config_standard.json for a given IP.
            #ShouldWork (Lookup Function)
        """
        for name, networks in self.zones.items():
            for network in networks:
                if ip.ip_address(addr) in network:
                    return name
        return 'Internet'

    @staticmethod
    def get_possible_previous_stages(stages: list[str]) -> set:
        """
        Returns a combined set of APT stages that could be a logical pre-condition to any of the passed APT `stages`.
        """
        previous_stages = set()
        for stage in stages:
            previous_stages.update(AptContextualizer.apt_preconditions[stage])
        return previous_stages

    @staticmethod
    def get_possible_following_stages(stages: list[str]) -> set:
        """
        Returns a combined set of APT stages that could be a logical post-condition to any of the passed APT `stages`.
        """
        following_stages = set()
        for stage in stages:
            following_stages.update(AptContextualizer.apt_postconditions[stage])
        return following_stages

    @staticmethod
    def get_static_stages(stages):
        """
        Returns all static stages that are contained in the given stages, if any. Returns an empty set otherwise.
        """
        return stages & AptContextualizer.host_stages

    @staticmethod
    def get_inbound_data(child_uid, parent_uid, parent_previous_stages, nodes) -> set or None:
        # rather potential child
        child_data = nodes[child_uid]
        parent_data = nodes[parent_uid]

        # child APT stages could have preceeded the parents APT stages
        # intersection but why with previous stages?
        # probably because the structure is reverse, it means the child before after the parent in time
        # if preconditions are met and parent younger than child;
        matching_parent_preconditions = set(child_data['stages']) & parent_previous_stages
        if parent_data['earliest'] > child_data['latest'] and matching_parent_preconditions:
            if child_data['target'] == parent_data['source']:
                transition_stages = AptContextualizer.get_static_stages(matching_parent_preconditions)
                if transition_stages:
                    return transition_stages

            # infection movement, target of previous alert becomes source of next alert
            if child_data['target'] & parent_data['source']:
                # malware movement in internal network
                transition_stages = AptContextualizer.get_movement_stages(matching_parent_preconditions)
                if transition_stages:
                    return transition_stages

                # malware delivery from internet to internal zone
                transition_stages = AptContextualizer.get_drop_stages(matching_parent_preconditions)
                if transition_stages:
                    return transition_stages

            # malicious action from infected nodes. sources are the same for two subsequent alerts
            if child_data['source'] & parent_data['source']:
                # internal target
                transition_stages = AptContextualizer.get_internal_action_stages(matching_parent_preconditions)
                if transition_stages:
                    return transition_stages

                # external target (CnC, Exfiltration) or malware download (eg. via dropper). internal node loads from
                # internet
                transition_stages = AptContextualizer.get_external_action_stages(matching_parent_preconditions)
                if transition_stages:
                    return transition_stages

            # reconnaissance
            # return AptContextualizer.get_recon_stages(matching_parent_preconditions)
            if AptContextualizer.check_locality(child_uid, parent_uid):
                return AptContextualizer.get_recon_stages(matching_parent_preconditions)
        return None

    @staticmethod
    def get_stage_aggregations_accross_many(stage_aggregations_per_alert, meta_alert_uids):
        """
        Returns a merged view on the data in `stage_aggregations_per_alert` aggregated accross all uids in
        `meta_alert_uids`.
        """
        merged = defaultdict(dict)
        for alert_uid in meta_alert_uids:
            for stage, agg in stage_aggregations_per_alert[alert_uid].items():
                merged[stage]['target'] = merged[stage].get('target', set()) | agg['target']
                merged[stage]['source'] = merged[stage].get('source', set()) | agg['source']
                merged[stage]['child_uids'] = (merged[stage].get('child_uids', set()) | agg['child_uids'])
        return merged

    @staticmethod
    def aggregate_node(params):
        """This fuck is essential; So how does it stuff?

        """
        (kv, nodes) = params
        (uid, data) = kv

        # preconditions(parent[stages])
        prev_stages = AptContextualizer.get_possible_previous_stages(data['stages'])

        agg = defaultdict(dict)
        referenced = set()

        # see every node as potential child
        for child_uid, child_data in nodes.items():
            # skip own node
            if child_uid == uid:
                continue
            # decision if child relationship exists
            stages = AptContextualizer.get_inbound_data(child_uid, uid, prev_stages, nodes)

            if stages:
                # aggregate data about source and target nodes
                stages = AptContextualizer.serialize_set(stages)
                agg[stages]['source'] = agg[stages].get('source', set()) | child_data['source']
                agg[stages]['target'] = agg[stages].get('target', set()) | child_data['target']
                agg[stages]['child_uids'] = (agg[stages].get('child_uids', set()) | {child_uid}) - {uid}
                referenced.add(child_uid)

        return uid, agg, referenced

    @staticmethod
    def new_infection_spread_tree(start_uid, start_node) -> tuple[str, str, nx.DiGraph]:
        """
            Returns a new infection spread tree that has its root at `start_uid` and contains one edge.
             Ultimately, the tree aggregates all nodes that are reachable from the `start_node`.
             #ShouldWork Only sets stuff up
        """
        digraph = nx.DiGraph(uid=start_uid)
        first_child = AptContextualizer.rand_uid()
        root = AptContextualizer.rand_uid()
        digraph.add_node(first_child, alerts=[start_uid])
        digraph.add_edge(first_child, root, stages=start_node['stages'], source=start_node['source'],
                         target=start_node['target'])

        return root, first_child, digraph

    def new_ukc(self, start_node, second_node, source, target, stages):
        """
        Returns a new minimal ukc conform graph. The only two nodes in the graph are `start_node` and `second_node`.
        The transition `stages` are required to build the correct labels.
        """

        UKC = nx.DiGraph(name=AptContextualizer.rand_uid())
        if not stages & AptContextualizer.ukc_start_stages:
            rand_start = AptContextualizer.rand_uid()
            UKC.add_node(rand_start, ips=set())
            UKC.add_edge(rand_start, start_node, stages=AptContextualizer.ukc_unknown_start_stage)

        infected_ips, target = self.shorten_label_for_source_target(source, target, stages)

        UKC.add_node(start_node, ips=infected_ips)
        UKC.add_node(second_node, ips=target)
        UKC.add_edge(start_node, second_node, stages=stages)
        return UKC

    def append_to_ukc(self, prev, current, edge_data, ukc=None):
        """
        Appends the edge (prev, current) to the ukc, if the source and target IPs for the APT stage in the edge_data
        match. The nodes in the ukc only carry shared IPs, not combined IPs. When a match is not possible,
        no edge is added to the ukc. Returns the new ukc and a boolean flag whether the update was possible.
        """
        if not ukc:
            return self.new_ukc(prev, current, edge_data['source'], edge_data['target'], edge_data['stages']), True

        # stages = edge_data['stages']
        prev_edge_label = list(ukc.in_edges(prev, data='stages'))[0][2]
        infection_movement_on_previous_edge = prev_edge_label & AptContextualizer.infection_movement_stages
        # Does not work good

        while prev_edge_label != AptContextualizer.ukc_unknown_start_stage and not infection_movement_on_previous_edge \
                and len(ukc.in_edges(prev)):
            prev = list(ukc.in_edges(prev))[0][0]
            prev_edge_label = list(ukc.in_edges(prev, data='stages'))[0][2] if len(ukc.in_edges(prev)) else None
            infection_movement_on_previous_edge = prev_edge_label & AptContextualizer.infection_movement_stages if \
                prev_edge_label else False

        # check if we can prolong the ukc. is the current transition (prev -> current) a valid post-condition to the
        # existing ukc stages?

        if not prev_edge_label or prev_edge_label == AptContextualizer.ukc_unknown_start_stage:
            allowed_transitions = set(AptContextualizer.apt_postconditions.keys())
        else:
            allowed_transitions = AptContextualizer.get_possible_following_stages(prev_edge_label)

        transition = edge_data['stages'] & allowed_transitions
        prev_ips = ukc._node[prev]['ips']  # is read-only access -> no problem
        infected_ips = prev_ips & edge_data['source']

        if not transition or (prev_edge_label != AptContextualizer.recon_stages and not infected_ips):
            return ukc, False

        stage_preferences = [AptContextualizer.get_movement_stages(transition),
                             AptContextualizer.get_internal_action_stages(transition),
                             AptContextualizer.get_external_action_stages(transition),
                             AptContextualizer.get_drop_stages(transition),
                             AptContextualizer.get_recon_stages(transition),
                             AptContextualizer.get_static_stages(transition)]
        stages = next((st for st in stage_preferences if st), None)

        if not stages:
            return ukc, False

        target = edge_data['target']
        if AptContextualizer.get_movement_stages(stages):
            target -= infected_ips

        if not target:
            return ukc, False

        infected_ips, target = self.shorten_label_for_source_target(infected_ips, target, stages)

        ukc.add_node(prev, ips=infected_ips)

        # check if there already exists an edge with these stages, update uuid of that node to be 'current'
        node_names = {v: (current if out_stages == stages else v) for _, v, out_stages in
                      ukc.out_edges(prev, data='stages')}
        ukc = nx.relabel_nodes(ukc, node_names, copy=False)
        ukc.add_node(current, ips=target)
        ukc.add_edge(prev, current, stages=stages)

        return ukc, True

    def shorten_label_for_source_target(self, source, target, stages):
        """
            Shortens the label for nodes in an ukc graph.
        """
        if stages & AptContextualizer.external_stages and len(target) > 5:
            zones = set()
            for addr in target:
                zones.add(self.get_network_zone(addr))
            target = zones
        if stages & AptContextualizer.ukc_start_stages and len(source) > 5:
            zones = set()
            for addr in source:
                zones.add(self.get_network_zone(addr))
            source = zones
        return source, target

    def split_spread_tree_to_ukc_scenarios(self, spread_tree, root):
        """
        Takes an infection spread tree. The edges must be labelled with APT stages. Returns a list of subtrees. Each
        subtree is a valid, ukc conform APT scenario. The scenarios are guaranteed to be of maximal length.
        """

        leaves = [node for node in spread_tree if spread_tree.in_degree(node) == 0]
        scenarios = []

        # traverse all paths that lead from a leave in the infection tree to the root
        for leave in leaves:
            for simple_path in all_simple_paths(spread_tree, leave, root):
                UKC = None
                for child, parent in nx.utils.pairwise(simple_path):
                    edge_data = spread_tree.edges[child, parent]
                    UKC, updated = self.append_to_ukc(child, parent, edge_data, UKC)
                    if not updated:
                        if not is_empty(UKC):
                            scenarios.append(UKC)
                        # try again to fork a new ukc (gets initialized by function if ukc=None)
                        UKC, updated = self.append_to_ukc(child, parent, edge_data)
                        if not updated:  # why is here error checking?
                            break
                if not is_empty(UKC):
                    scenarios.append(UKC)

        return scenarios

    @staticmethod
    def check_locality(child_uid: str, parent_uid: str) -> bool:

        child_direction = child_uid.split('_', 1)
        parent_direction = parent_uid.split('_', 1)

        # if directions are the same for R & D1; e.g: Internet->Dep_1
        return child_direction[1] == parent_direction[1]

    def build_dict_of_apt_preconditions(self, earliest_date, latest_date, date_format):
        alerts = self.get_alerts(earliest_date=earliest_date, latest_date=latest_date, date_format=date_format,
                                 cache=self.cache)
        num_alerts = len(alerts)
        print(f'{datetime.now()}: processing {num_alerts} meta-alerts')

        start = time.time()
        nodes = defaultdict(dict)

        # alert to node structure
        for idx, ma in enumerate(alerts):
            try:
                nma = self.normalize_alert(ma)
                earliest_ts, latest_ts = self.get_alert_details(nma)
            except Exception as e:
                logging.exception(e)
                continue  # do not handle alert at all
            directions = self.get_directions(meta_alert=nma)

            for direction, involved_ips in directions.items():
                if 'stages' in ma and self.mapping:
                    stages = set(ma['stages']) if ma['stages'] else \
                        AptContextualizer.get_potential_apt_stages(direction)
                else:
                    stages = AptContextualizer.get_potential_apt_stages(direction)
                if not AptContextualizer.is_valid_assignment(stages, direction):
                    logging.info("Alert not used: " + str(ma) + ' ' + str(direction))
                    continue
                # construct one node; data structure: dict[dict]
                if '->host' in direction:
                    n_zone = direction.split('->')
                    direction = direction.replace('host', n_zone[0])
                node_id = f'{nma["uid"]}_{direction}'
                nodes[node_id]['stages'] = stages
                nodes[node_id]['ts'] = nma['ts']
                nodes[node_id]['source'] = involved_ips['source']
                nodes[node_id]['target'] = involved_ips['target']
                nodes[node_id]['earliest'] = earliest_ts
                nodes[node_id]['latest'] = latest_ts

            if idx % 100 == 0:
                print(f'{datetime.now()}: {idx}/{num_alerts} ({idx / num_alerts * 100}%)')

        print(f'{datetime.now()}: processed {num_alerts} meta-alerts in {time.time() - start} seconds')
        num_nodes = len(nodes)

        print(f'{datetime.now()}: aggregating {num_nodes} nodes')
        start = time.time()
        referenced_children = set()
        stage_aggregations_per_alert = dict()

        print(f'{datetime.now()}: allocating manager + array')
        with multiprocessing.Manager():
            pool = multiprocessing.Pool(processes=self.max_procs)
            idx = 0
            print('{}: starting pool loop'.format(datetime.now()))

            for res in pool.imap_unordered(AptContextualizer.aggregate_node, zip(nodes.items(), repeat(nodes)),
                                           chunksize=100):
                (uid, agg, referenced) = res
                referenced_children = referenced_children.union(referenced)
                stage_aggregations_per_alert[uid] = agg

                idx += 1
                if idx % 100 == 0:
                    print('{}: {}/{} ({}%)'.format(datetime.now(), idx, num_nodes, idx / num_nodes * 100))

            pool.close()
        print('{}: aggregated {} nodes in {} seconds'.format(datetime.now(), num_nodes, time.time() - start))

        unreferenced_uids = set(stage_aggregations_per_alert.keys()) - referenced_children
        unreferenced_nodes = {unref_uid: nodes[unref_uid] for unref_uid in unreferenced_uids}

        return stage_aggregations_per_alert, unreferenced_nodes, nodes

    def recurse_append_spread_tree(self, stage_aggregations_per_alert, meta_alert_uids, parent_node, rename,
                                   used_alerts=None):
        """
        Appends to an infection spread tree `rename`. Starting at node `parent_node` all `meta_alert_uids` are
        combined as children. The combination merges all those children that transition to the `parent_node` with the
        same APT stages.

            Example: all children with the exact same transitions like [CnC, Exfiltration] are merged into one single
            transition and one big child node.

            The resulting tree resembles an infection spread that is possible in terms of communicating src/dst node
            IPs, as well as correct in terms of POTENTIAL pre- and post-conditions of ukc infection stages. The pre-
            and post-conditions are potentially possible with the given alerts. That does not follow that the paths
            in the tree resemble a correct ukc conform scenario. (For splitting the tree at impossible paths see
            `self.split_spread_tree_to_ukc_scenarios`).
        """

        if used_alerts is None:
            used_alerts = set()

        merged_stage_aggs = AptContextualizer.get_stage_aggregations_accross_many(stage_aggregations_per_alert,
                                                                                  meta_alert_uids)
        used_alerts.update(meta_alert_uids)

        order = ['L', 'P', 'O', 'H', 'S', 'E', 'C', 'D1', 'D2', 'R']

        # make sure the longest chain of infection spread is traversed (if possible)
        # therefore, iterate aggregated items in 'order' of preferred stages
        for stages, aggregation in sorted(merged_stage_aggs.items(), key=lambda x: order.index(
                sorted(AptContextualizer.deserialize_set(x[0]),
                       key=lambda y: order.index(y))[0])):

            stages = AptContextualizer.deserialize_set(stages)
            if not stages:
                continue

            child_node = AptContextualizer.rand_uid()

            stage_preferences = [AptContextualizer.get_movement_stages(stages),
                                 AptContextualizer.get_internal_action_stages(stages),
                                 AptContextualizer.get_external_action_stages(stages),
                                 AptContextualizer.get_drop_stages(stages),
                                 AptContextualizer.get_recon_stages(stages),
                                 AptContextualizer.get_static_stages(stages)]

            stages = next((st for st in stage_preferences if st), None)
            children = aggregation['child_uids'] - used_alerts

            # Build Graph
            if stages and children:
                rename.add_node(child_node, alerts=children)
                rename.add_edge(child_node, parent_node, stages=stages, target=aggregation['target'],
                                source=aggregation['source'])
                if stages != AptContextualizer.recon_stages:
                    rename, used_alerts = self.recurse_append_spread_tree(stage_aggregations_per_alert, children,
                                                                          child_node, rename, used_alerts)

        return rename, used_alerts

    @staticmethod
    def stages_stats(stage_aggregations_per_alert: dict) -> dict:
        stats = {
            'empty': 0
        }
        for entry in stage_aggregations_per_alert:
            if not stage_aggregations_per_alert[entry].keys():
                stats['empty'] += 1
            for key in stage_aggregations_per_alert[entry].keys():
                if key in stats:
                    stats[key] += 1
                else:
                    stats[key] = 1

        return stats

    @staticmethod
    def create_meta_information(ukc_scenarios: list) -> (list, dict):
        meta = {}
        for ukc in ukc_scenarios:
            meta[ukc.name] = {
                'score': 50
            }
        return ukc_scenarios, meta

    def trace_context_before(self, earliest_date=None, latest_date=None, date_format=None):
        """
        Traces the APT context that happened temporally before the given timestamp. Tries to build stories APT
        stories along the Unified Kill Chain (ukc).
        """

        if earliest_date:
            print(f'{datetime.now()}: building memory map of pre- and post-conditions in alerts before {earliest_date}')

            # Main Calculation and research
            start = time.time()
            stage_aggregations_per_alert, unreferenced_nodes, nodes = self.build_dict_of_apt_preconditions(
                earliest_date, latest_date, date_format)
            print(f'{datetime.now()}: done after {time.time() - start}')

            # store in-mem maps for easier life while debugging, uncomment as needed:
            store_to_file(stage_aggregations_per_alert, 'stage_aggs_original')
            store_to_file(unreferenced_nodes, 'unref_original')
            store_to_file(nodes, 'nodes')
        else:
            stage_aggregations_per_alert = restore_from_file('stage_aggs_original')
            unreferenced_nodes = restore_from_file('unref_original')
            nodes = restore_from_file('nodes')

        print(f'{datetime.now()}: source data, spread in unique directions: {len(stage_aggregations_per_alert)}')

        if not os.path.isdir("out"):
            mkdir("out")

        stage_aggregations_per_alert = Optimization.pre_optimization(alerts=stage_aggregations_per_alert,
                                                                     level=0, max_procs=self.max_procs)
        # Just counting child relationships; Reset host direction
        c = 0
        for s in stage_aggregations_per_alert.values():
            for a in s.values():
                c += len(a['child_uids'])

        print(self.stages_stats(stage_aggregations_per_alert))

        UKC_scenarios, spread_trees, roots = [], [], []
        num_unreferenced = len(unreferenced_nodes)
        print(f'{datetime.now()}: crunching {c} child-relations to {num_unreferenced} spread-graphs...\n')

        # Build Spread Graphs
        start = time.time()
        for idx, (start_uid, start_node) in enumerate(unreferenced_nodes.items()):

            # build infection spread tree based on pre- and post-conditions
            root, first_child, spread_tree = AptContextualizer.new_infection_spread_tree(start_uid, start_node)
            spread_tree, _ = self.recurse_append_spread_tree(stage_aggregations_per_alert, [start_uid], first_child,
                                                             spread_tree)
            spread_trees += [spread_tree]
            roots += [root]
            # AptContextualizer.draw_spread_tree(spread_tree, 'spread_' + start_uid, compact=False)

            if idx % 10 == 0:
                print(f'{datetime.now()}: {idx}/{num_unreferenced} ({idx / num_unreferenced * 100})')
        if self.gca:
            spread_trees, root = Optimization.optimization(spread_graphs=spread_trees, level=self.opt_level,
                                                           max_procs=self.max_procs, alerts=nodes,
                                                           events=self.get_events())
            roots += root

        # Split UKC Scenarios
        for index, (spread_tree, root) in enumerate(zip(spread_trees, roots)):
            AptContextualizer.draw_spread_tree(spread_tree, 'spread_' + str(index), compact=False)
            scenarios = self.split_spread_tree_to_ukc_scenarios(spread_tree, root)
            UKC_scenarios += scenarios

        UKC_scenarios, UKC_meta = AptContextualizer.create_meta_information(ukc_scenarios=UKC_scenarios)
        UKC_scenarios, UKC_meta = Prioritization.prioritization(ukc=UKC_scenarios, max_procs=self.max_procs,
                                                                zones=self.config.get('zones'), meta=UKC_meta)
        UKC_scenarios = Optimization.post_optimization(ukc=UKC_scenarios, level=self.opt_level,
                                                       max_procs=self.max_procs)
        print('{}: total ukc scenarios: {}'.format(datetime.now(), len(UKC_scenarios)))

        # Saving UKC Scenarios
        num_scenarios = len(UKC_scenarios)
        print('{}: persisting {} scenarios to graphml/pdf...'.format(datetime.now(), num_scenarios))
        start = time.time()
        for idx, scenario in enumerate(UKC_scenarios):
            AptContextualizer.persist_ukc(ukc=scenario, file_name=f'ukc_{idx}', meta=UKC_meta[scenario.name])
            if idx % 10 == 0:
                print('{}: {}/{} ({}%)'.format(datetime.now(), idx, num_scenarios, idx / num_scenarios * 100))
        print(f'{datetime.now()}: persisted {num_scenarios} scenarios in {time.time() - start} seconds')
        print('Well done Sir! Dismissed!')

    def run(self, arg):
        """The main loop. It can communicate via non-blocking asychronous queues with the sending and receiving
        subprocesses. """
        if arg == 'local':
            self.trace_context_before()
        else:
            self.integrate()
            self.trace_context_before(self.config['earliest_date'], self.config['latest_date'],
                                      self.config['date_format'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="APT-Contextualizer")
    parser.add_argument('config', help="Path to configuration file")
    parser.add_argument('-m', '--mode', help="Modes: local, None: Standard")
    parser.add_argument('-o', '--optimization', type=int, help="Optimization Level 0, 1, (2)", default=1)
    parser.add_argument('-p', '--prioritization', help="True/False", action='store_true')
    parser.add_argument('-sm', '--mapping', help="Alert Mapping: True/False", action='store_true')
    parser.add_argument('-pt', '--ptreshold', type=int, help="Prune below Int 0-100", default=0)
    parser.add_argument('-st', '--streshold', type=int, help="Save above Int 0-100", default=101)
    parser.add_argument('-so', '--objective', help="Strict mode: 0, 1", action='store_true')
    parser.add_argument('-nee', '--event', help="Mode: 0, 1", action='store_true')
    parser.add_argument('-gca', '--gcalgorithm', help="Mode: 0, 1", action='store_true')
    args = parser.parse_args()

    path = "" if os.getcwd().endswith("apt_contextualizer") else f'apt_contextualizer/'
    warnings.filterwarnings("ignore")
    apt_contextualizer = AptContextualizer(args)
    apt_contextualizer.run(args.mode)
