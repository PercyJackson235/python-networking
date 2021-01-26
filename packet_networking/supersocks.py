import socket


class SuperSock(object):
    def __init__(self, family=socket.AF_INET, socktype=socket.SOCK_STREAM, proto=0):  # noqa: E501
        self.ins = socket.socket(family, socktype, proto)
        self.outs = self.ins


class L3Socket(SuperSock):
    def __init__(self, proto=None, interface: str = None):
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # noqa: E501
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))  # noqa: E501
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)  # noqa: E501
        self.sock.bind(('eth0', socket.IPPROTO_ICMP))
