APT Contextualizer
==================

This is the reference implementation for Chapter 4 of my Master's Thesis -- the `apt-contextualizer`. It implements the `broker_base` application and uses the `elasticsearch_client`.

## Configure & Run

Start the application with `python3`:

    $ python apt-contextualizer.py config.json

Configure the application with the `config.json` file.

#### Elastic Search

For elasticsearch connection you will need a config block that specifies the address of elasticsearch

```
"elastic_search": {
    "addr": "127.0.0.1",
    "port": 9200
}
```

#### Network Zones

The APT-contextualizer requires a network zone configuration. Provide the individual zones as JSON pairs, the value is a comma delimitted list of CIDR subnets.

For example, you have two zones

- zone_1: 172.16.0.0 .... 172.16.255.255
- zone_2: 172.17.0.0 .... 172.31.255.255

That would result in the following config entry

```
"zones": {
    "Zone_1": "172.16.0.0/16",
    "Zone_2": "172.17.0.0/16,172.18.0.0/15,172.20.0.0/14,172.24.0.0/13"
}
```
#### Analysis Date Range

The contextualizer queries elasticsearch for `high-level` alerts. You have to configure the date range in which to operate.

```
"earliest_date": "01/01/2018",
"latest_date": "now",
"date_format": "dd/MM/yyyy"
```
#### Example Configs


```
{
    "zones": {
        "Zone_1": "172.16.0.0/16",
        "Zone_2": "172.17.0.0/16,172.18.0.0/15,172.20.0.0/14,172.24.0.0/13"
    },
    "elastic_search": {
        "addr": "127.0.0.1",
        "port": 9200
    },
    "earliest_date": "01/01/2018",
    "latest_date": "now",
    "date_format": "dd/MM/yyyy"
}
```