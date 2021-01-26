import socket
from . import utils
import ipaddress


def send():
    """send packet"""
    pass


def sr():
    """send and receive packet"""
    pass


def send1():
    """send one packet"""
    pass


def sr1():
    """send packet and receive one packet"""
    pass


def sendloop():
    """send packet in a loop"""
    pass


def srloop():
    """send and receive in a loop"""
    pass


def ping():
    """send ICMP ping request"""
    pass


# Windows Default
def icmptraceroute(dst: str = None, src: str = None, ttl: int = None):
    """send an ICMP traceroute"""
    dst = ipaddress.ip_address(dst)


def tcptraceroute():
    """send an TCP traceroute"""
    pass


def udptraceroute():  # Unix-Like Default
    """send an UDP traceroute"""
    pass


if utils.ttl_check() == 128:
    def defualtTraceroute():
        icmptraceroute()
else:
    def defualtTraceroute():
        udptraceroute()
