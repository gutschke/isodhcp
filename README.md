# isodhcp - Isolated DHCP Server for Point-To-Point Clients

In cases where a router or switch cannot provide native support for
client isolation, a similar effect can be achieved by using a DHCP
server that only ever hands out Point-To-Point host routes for all
clients.

This forces network traffic through the router's networking stack
avoiding the level 2 network switch, and you can then use normal
firewall rules to make traffic decisions.

The daemon doesn't have any configuration file and is configured
through the command line. At the very least, you should specify the
name of the network interface that all isolated DHCP clients are
connected to.

It is recommended to set up a Python venv, and you probably will
need to install the scapy and pyroute2 Python packages. An example
systemd service file is included but will need customization for
the local system.
