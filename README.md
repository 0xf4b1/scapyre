# scapyre

A tool to replay network captures (PCAP files) inside a network end-to-end, e.g. by using Docker containers

## Requirements

To use the netfilter queue mode, some packages need to be installed.
On CentOS 7 the following packages are needed:

`gcc python2-devel libnfnetlink-devel libnetfilter_queue-devel`

Afterwards the python library can be installed:

`pip2 install netfilterqueue`
