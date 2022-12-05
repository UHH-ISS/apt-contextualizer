Elastic Search Client
=====================

Light weight client abstraction for communication with elasticsearch.
All relevant queries are defined here, such that applications don't need to know any of the underlying database structure.

The client is meant to be imported by other python classes. Make sure your `$PYTHONPATH` is set correctly.


```
import broker
from broker_base.broker_application import BrokerApplication


from elasticsearch_client.client import Client

class SampleApp(BrokerApplication):

    def __init__(self, config_path):
        super().__init__(config_path)
        
        self.es_client = None
        es_config = self.config.get('elastic_search')
        if es_config:
            print('Found Elasticsearch config.')
            self.es_client = Client(es_config['addr'], es_config['port'])

    .... rest of your code ....
```


## Elasticsearch Schemas

The client implementation provides the ES schema definitions. When the client is used to store elements, these schema definitions can be used to specify how elements are indxed.

## Queries

The query extensions provided by the client are pretty much self explanatory. See the `client.py` implementation and method comments.
