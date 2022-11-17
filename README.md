# uhh-iss/apt-contextualizer

## About (TODO)

## Get Started (WIP)

Set your python path so that you can use and import the libraries and applications:

    $ export PYTHONPATH=$PYTHONPATH:/home/<you>/<whatever>/apt_contextualizer

### Configuration File - Fields

- elastic_search[optional]
  - addr[for cluster]
  - port[for cluster]
  - indices[for cluster]
- cache
- event_cache[optional]
- earliest_date[for cluster]
- latest_date[for cluster]
- date_format[for cluster]
- max_procs
- zones:
  - Name for Network Zone:
     - Subnet
     - Severity[if priority is used]
(has to be done for every Network Zone)


### CLI Options

- config: path to File
- mode[optional]: local
- optimization[optional], default 1
- prioritization[optional]
- mapping[optional]
- ptreshold[optional]: Int 0-100
- streshold[optional]: Int 0-100
- objective[optional]
- event[optional]
- gcalgorithm[optional]


## Contributors

- [Florian Wilkens (1wilkens)](https://github.com/1wilkens)
- [Felix Ortmann (0snap)](https://github.com/0snap)
- [Jona Laudan (stayhett)](https://github.com/Stayhett)

## License (MIT)
