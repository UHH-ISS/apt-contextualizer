from datetime import datetime, timezone
import json

from thehive4py.api import TheHiveApi
from thehive4py.query import Between, Eq

from util import util


DATE_FMT = '%d/%m/%Y'


def parse_date(date_str: str) -> datetime:
    if date_str == 'now':
        return datetime.now(timezone.utc)
    return datetime.strptime(date_str, DATE_FMT).replace(tzinfo=timezone.utc)


def _log(msg: str):
    util.log(msg, "backend/thehive")


class Client:

    def __init__(self, url, apikey):
        # FIXME: cert check
        self.api = TheHiveApi(url, apikey, cert=False)
        _log(f"connected to TheHive instance @ {url}", )

    def get_alerts(self, from_date: str, to_date: str):
        from_date = parse_date(from_date)
        to_date = parse_date(to_date)
        _log(f"getting alerts between {from_date.date()} and {to_date.date()}")
        query = Between('date', from_date.timestamp() * 1000, to_date.timestamp() * 1000)
        resp = self.api.find_alerts(query=query, sort=['+createdAt'], range='all')
        alerts = resp.json()
        _log(f"got {len(alerts)} alert(s)")
        return alerts

    #def store_alert(self, index, alert, refresh=False):
    #    res = self.es.index(index=index, id=alert['uid'], body=alert, refresh=refresh)
    #    # print('{} -- {} {}'.format(res['result'], index, res['_id']))
    #    return res

    ## TODO: Reimplement; Should be used for elastic output
    #def bulk_store(self, alert_generator, index):
    #    """stores all alerts in the generator in a bulk fashion"""
    #    res = bulk(self.es, self.__wrap_alert_generator_to_elaticsearch_actions(alert_generator, index))
    #    return res

    #def query_daterange(self, index, earliest_date, latest_date, date_format, or_attrs=None):
    #    """
    #    Runs a scan query against elasticsearch to entries from a configurable index in the wanted date-range. If
    #    `corr_name` is specified, it will only query weak alerts that were classified by `corr_name` (e.g. GAC).
    #    Accepts an optional `or_attrs` parameter. Has to be a list of tuples with (key, val) pairs for elasticsearch.
    #    Returns all hits in a paginated fashion.
    #    #Works
    #    """
    #    if or_attrs is None:
    #        or_attrs = []
    #    query = {
    #        'query': {
    #            'bool': {
    #                'must': [
    #                    {'range': {'@timestamp': {
    #                        'gte': earliest_date,
    #                        'lte': latest_date,
    #                        'format': date_format
    #                    }}}
    #                ],
    #                'should': [],
    #                'minimum_should_match': 1 if len(or_attrs) > 0 else 0
    #            }
    #        }}
    #    # if corr_name:
    #    #     query['query']['bool']['must'].append({'match': {'name': corr_name}})
    #    for key, val in or_attrs:
    #        query['query']['bool']['should'].append({'term': {key: val}})
    #    for hit in scan(self.es, index=index, query=query, scroll='30m'):
    #        yield hit['_source']

    #def get_by_uid(self, uid_list, index_list=None):
    #    """
    #        Queries one or more alerts by UID.
    #        Returns an iterator
    #        #DoesNotWork
    #    """
    #    if index_list is None:
    #        index_list = ['logs_zeek']
    #    if type(uid_list) == str:
    #        uid_list = [uid_list]
    #    for uid in uid_list:
    #        query = {
    #            'query': {
    #                'bool': {'must': [
    #                    {'match': {'zeek.session_id': uid}}
    #                ]}
    #            }}
    #        res = self.es.search(index=index_list, body=query)
    #        hits = res.get('hits')
    #        if hits is None:
    #            break
    #        hits = hits['hits']  # unwrap second layer
    #        yield hits[0]['_source']

    #def query_attributes(self, index, and_attrs, or_attrs=None):
    #    """
    #        Queries an exact match of all key-value pairs in the past dictionary.
    #        Returns all hits as array.
    #    """
    #    if or_attrs is None:
    #        or_attrs = []
    #    query = {
    #        'query': {
    #            'bool': {
    #                'must': [],
    #                'should': [],
    #                'minimum_should_match': 1 if len(or_attrs) > 0 else 0
    #            }
    #        }
    #    }
    #    for key, val in and_attrs.items():
    #        query['query']['bool']['must'].append({'match': {key: val}})
    #    for key, val in or_attrs:
    #        query['query']['bool']['should'].append({'term': {key: val}})
    #    for hit in scan(self.es, index=index, query=query, scroll='30m'):
    #        yield hit['_source']

    #def query_nested_attributes(self, index, nested_path, nested_and_attrs=None, nested_or_attrs=None, and_attrs=None,
    #                            or_attrs=None):
    #    """
    #        Queries an exact match of all key-value pairs in the given dictionary.
    #        Returns all hits as array.
    #    """
    #    if or_attrs is None:
    #        or_attrs = list()
    #    if and_attrs is None:
    #        and_attrs = []
    #    if nested_or_attrs is None:
    #        nested_or_attrs = []
    #    if nested_and_attrs is None:
    #        nested_and_attrs = []
    #    nested_and = {
    #        'nested': {
    #            'config_path': nested_path,
    #            'query': {
    #                'bool': {
    #                    'must': []
    #                }
    #            }
    #        }
    #    }
    #    nested_or = {
    #        'nested': {
    #            'config_path': nested_path,
    #            'query': {
    #                'bool': {
    #                    'must': []
    #                }
    #            }
    #        }
    #    }
    #    query = {
    #        'query': {
    #            'bool': {
    #                'must': [],
    #                'should': [],
    #                'minimum_should_match': 1 if len(or_attrs) + len(nested_or_attrs) > 0 else 0
    #            }
    #        }
    #    }
    #    if nested_and_attrs:
    #        for key, val in nested_and_attrs.items():
    #            nested_and['nested']['query']['bool']['must'].append({'match': {key: val}})
    #        query['query']['bool']['must'].append(nested_and)
    #    if nested_or_attrs:
    #        for key, val in nested_or_attrs.items():
    #            nested_or['nested']['query']['bool']['must'].append({'match': {key: val}})
    #        query['query']['bool']['should'].append(nested_or)

    #    for key, val in and_attrs.items():
    #        query['query']['bool']['must'].append({'match': {key: val}})
    #    for key, val in or_attrs:
    #        query['query']['bool']['should'].append({'term': {key: val}})
    #    for hit in scan(self.es, index=index, query=query, scroll='30m'):
    #        yield hit['_source']

    #@staticmethod
    #def parse_timestamp(ts_string):
    #    """
    #        Returns a python datetime object. parses the given string, which has to be in ES date format.
    #    """
    #    for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S'):
    #        try:
    #            return datetime.strptime(ts_string, fmt).replace(tzinfo=None)
    #        except ValueError:
    #            pass
    #    print("could not parse this date:", ts_string)
    #    return None

    #def get_all(self, index_list):
    #    """Returns an iterator over all elements in the given ES index(es)"""
    #    query = {'query': {'match_all': {}}}
    #    for hit in scan(self.es, index=index_list, query=query, scroll='30m'):
    #        yield hit['_source']

