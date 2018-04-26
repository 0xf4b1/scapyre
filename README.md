# scapyre

A tool to replay network captures (PCAP files) inside a network end-to-end, e.g. by using Docker containers

## Requirements

* python2
* scapy
* netfilterqueue (optional)

To use the netfilter queue mode, some packages need to be installed.
On CentOS 7 the following packages are needed:

`gcc python2-devel libnfnetlink-devel libnetfilter_queue-devel`

Afterwards the python library can be installed:

`pip2 install netfilterqueue`

## Starting a replay

`python2 scapyre.py <pcap> <interface> <ip> [--mapping <mapping>]`

## Docker

Building a Docker container that contains the replay tool

`docker build -t scapyre .`

Running the docker container

`docker run -it -v <pcap directory>:/data --network <docker network> --ip <container ip> scapyre <replay params>`

Create docker network for replay

`docker network create --subnet "10.0.0.0/8" scapyre`

Example with two hosts

`docker run -it --network scapyre --ip 10.18.0.2 scapyre 2016-05-11_win4.pcap eth0 192.168.1.114 --mapping '{"192.168.1.114": "10.18.0.2", "default": "10.18.0.3"}'`

`docker run -it --network scapyre --ip 10.18.0.3 scapyre 2016-05-11_win4.pcap eth0 default --mapping '{"192.168.1.114": "10.18.0.2", "default": "10.18.0.3"}'`