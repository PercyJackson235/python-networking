import array
import socket
import struct
import random
from collections import namedtuple
from . import utils
from . import errors
from . import osi
from copy import deepcopy
from . import Fields


DEFAULT_TTL = utils.ttl_check()


class BasePacket(object):
    __slots__ = ("name", "full_packet")

    def __init__(self):
        self.name = self.__class__.__name__
        self.full_packet = None

    def __repr__(self):
        res = " | ".join(map(repr, self.full_packet))
        return f"<{self.name}| {res}>"

    def _checksum(self, pkt=None):
        if pkt is None:
            pkt = self.full_packet
        if len(pkt) % 2 == 1:
            pkt += b"\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff

    def __truediv__(self, other):
        if not isinstance(other, (BasePacket, str, bytes)):
            raise errors.InvalidPacketAdditionError()
        packets = []
        for pkt in (self, other):
            if isinstance(pkt, Packet):
                packets.extend(deepcopy(pkt.full_packet))
            else:
                packets.append(deepcopy(pkt))
        return Packet(*packets)

    def __div__(self, other):
        return self.__truediv__(other)

    def __add__(self, other):
        return self.__truediv__(other)

    def __rtruediv__(self, other):
        return self.__truediv__(other)

    def __radd__(self, other):
        return self.__truediv__(other)

    def __deepcopy__(self, memo: dict = None):
        if memo is not None:
            _copy = memo.get(id(self))
        else:
            _copy = None
        if _copy is None:
            if type(self) == Packet:
                packets = [deepcopy(pkt) for pkt in self.full_packet]
                _copy = self.__class__(*packets)
            else:
                interior = {}
                for attr in dir(self):
                    if not attr.startswith('_') and attr != "name":
                        interior[attr] = deepcopy(getattr(self, attr))
                _copy = self.__class__(**interior)
        return _copy

    def __copy__(self):
        return self.__deepcopy__()


IP_Lay_Pkt = namedtuple("IP_Layer_Packet", ["ip_ver_ihl", "tos", "total_length",  # noqa: E501
                                            "id", "offset", "ttl", "protocol",
                                            "checksum", "src_ip", "dst_ip",
                                            "options", "padding"], defaults=(None, None))  # noqa: E501

TCP_Lay_Pkt = namedtuple("TCP_Layer_Packet", ["src_port", "dst_port", "seq",
                                              "acknowledge", "offset_flags",
                                              "window", "checksum",
                                              "urgent_pointer", "options",
                                              "padding"], defaults=(None, None))  # noqa: E501

UDP_Lay_Pkt = namedtuple("UDP_Layer_packet", ["src_port", "dst_port", "length",
                                              "checksum"], defaults=(0,))


class Packet(BasePacket):
    """Packet is created by combinations of IP, TCP, UDP, RAW, bytes, or str.
       Example: IP() / TCP() / RAW()
       The Packet combination that will be returned will have an IP layer, then
       a TCP layer, and finally the RAW() layer. The Packet combination will
       always be from left to right, with the left most packet type as the
       lowest layer and the rest are stacked on top in that order.
       >>> IP() / TCP() + UDP()
       <Packet| <IP| dst=127.0.0.1, src=127.0.0.1, ttl=64> | <TCP| sport=64423,
       ... dport=80, flags=2> | <UDP| sport=51837, dport=53>>
       >>> Packet(IP(), TCP(), UDP())
       <Packet| <IP| dst=127.0.0.1, src=127.0.0.1, ttl=64> | <TCP| sport=64423,
       ... dport=80, flags=2> | <UDP| sport=51837, dport=53>>"""
    def __init__(self, *packets):
        super().__init__()
        if utils.packet_check(packets, self.__class__):
            if isinstance(packets[0], IP):
                try:
                    p = osi.PROTO_DICT.get(packets[1].full_packet[0].name, 200)
                    if p == 200:
                        raise errors.PacketOrderError()
                except AttributeError:
                    if isinstance(packets[1], Packet):
                        if hasattr(packets[1].full_packet[0].name):
                            a = osi.PROTO_DICT.get(packets[1].full_packet[0].name)  # noqa: E501
                            if a is None:
                                a = osi.PROTO_DICT['TCP']
                            packets[0].protocol = a
                    elif isinstance(packets[1], (str, bytes, int)):
                        pass
        else:
            if isinstance(packets[0], IP) and hasattr(packets[1], "name"):
                packets[0].protocol = osi.PROTO_DICT.get(packets[1].name, 200)
                if packets[0].protocol == 200 and type(packets[1]) != RAW:
                    if type(packets[1]) == BasePacket:
                        raise NotImplementedError("BasePacket is not to be used.")  # noqa: E501
                    else:
                        raise errors.PacketOrderError("Unknown Packet Type.")
        self.full_packet = packets


class IP(BasePacket):
    __slots__ = ["ip_ver", "ihl", "tos", "total_length", "id", "flags",
                 "frag_offset", "ttl", "protocol", "checksum", "src_ip",
                 "dst_ip", "options", "padding"]

    def __init__(self, **kwargs):
        super().__init__()
        self.ip_ver = kwargs.get("ip_ver", 4)  # first 4 bits
        self.ihl = kwargs.get("ihl", 5)  # last 4 bits, combined to ip_ver_ihl
        self.tos = kwargs.get("tos", 0)  # 1 byte
        self.total_length = kwargs.get("total_length", 0)  # 2 bytes
        self.id = kwargs.get("id", random.randint(100, (2 ** 16) - 6))  # 2 bytes  # noqa: E501
        self.flags = kwargs.get("flags", 0)  # first 3 bits, combined offset
        self.frag_offset = kwargs.get("frag_offset", 0)  # last 13 bits
        self.ttl = kwargs.get("ttl", DEFAULT_TTL)  # 1 byte
        self.protocol = kwargs.get("protocol", 0)  # 1 byte
        self.checksum = kwargs.get("checksum", 0)  # 2 bytes
        self.src_ip = kwargs.get("src_ip", "127.0.0.1")  # 4 bytes
        self.dst_ip = kwargs.get("dst_ip", "127.0.0.1")  # 4 bytes
        self.options = kwargs.get("options")
        self.padding = kwargs.get("padding")
        self.src_ip = socket.gethostbyname(self.src_ip)
        self.dst_ip = socket.gethostbyname(self.dst_ip)
        if self.src_ip == "127.0.0.1":
            self.src_ip = utils.routing_info(self.dst_ip)
            self.src_ip = Fields.IPv4Field(self.src_ip)
        else:
            self.src_ip = socket.gethostbyname(self.src_ip)
            self.src_ip = Fields.IPv4Field(self.src_ip)

    def _build_packet(self):
        pass

    def _pack(self, protocol=None, rerun: bool = False):
        packet = IP_Lay_Pkt((self.ip_ver << 4) + self.ihl, self.tos,
                            self.total_length, self.id,
                            (self.flags << 13) + self.frag_offset, self.ttl,
                            protocol if protocol else self.protocol,
                            self.checksum, socket.inet_aton(self.src_ip),
                            socket.inet_aton(self.dst_ip), self.options,
                            self.padding
                            )
        if rerun:
            return packet
        if not self.options:
            while True:
                bin_pkt = struct.pack('!BBHHHBBH4s4s', *[i for i in packet if i is not None])  # noqa: E501
                if not rerun:
                    self.checksum = self._checksum(bin_pkt)
                    packet = self._pack(rerun=True)
                else:
                    break
        else:
            raise NotImplementedError
        self.full_packet = bin_pkt

    def __repr__(self):
        return f"<{self.name}| dst={self.dst_ip}, src={self.src_ip}, ttl={self.ttl}>"  # noqa: E501


class TCP(BasePacket):
    __slots__ = ["src_port", "dst_port", "seq", "acknowledge", "data_offset",
                 "reserved", "flags", "window", "checksum", "urgent_pointer",
                 "options", "padding"]

    def __init__(self, **kwargs):
        super().__init__()
        self.src_port = kwargs.get("src_port", random.randint(34000, 65000))  # 2 bytes  # noqa: E501
        self.dst_port = kwargs.get("dst_port", 80)  # 2 bytes
        self.seq = kwargs.get("seq", random.randint(1, 2 ** 16))  # 4 bytes
        self.acknowledge = kwargs.get("acknowledge", 0)  # 4 bytes
        self.data_offset = kwargs.get("data_offset", 5)  # first 4 bits
        self.reserved = kwargs.get("reserved", 0)  # second 6 bits
        self.flags = kwargs.get("flags")  # last 6 bits, forms 2 bytes
        self.window = kwargs.get("window", 1500)   # 2 bytes
        self.checksum = kwargs.get("checksum", 0)  # 2 bytes
        self.urgent_pointer = kwargs.get("urgent_pointer", 0)  # 2 bytes
        self.options = kwargs.get("options")
        self.padding = kwargs.get("padding")
        if self.flags is None:
            self.flags = utils.flag_dict["S"]
        else:
            self.flags = utils.combine(utils.flag_check(self.flags))

    def _pack(self, rerun: bool = False):
        packet = TCP_Lay_Pkt(
            self.src_port, self.dst_port, self.seq, self.acknowledge,
            ((self.data_offset << 12) + (self.reserved << 6) + self.flags),
            self.window, self.checksum, self.urgent_pointer, self.options,
            self.padding
        )
        if rerun:
            return packet
        if not self.options:
            while True:
                bin_pkt = struct.pack('!HHLLHHHH', *[i for i in packet if i is not None])  # noqa: E501
                if not rerun:
                    self.checksum = self._checksum(bin_pkt)
                    packet = self._pack(rerun=True)
                else:
                    break
        else:
            raise NotImplementedError
        self.full_packet = bin_pkt

    def __repr__(self):
        msg = f"<{self.name}| sport={self.src_port}, dport={self.dst_port},"
        msg += f" flags={self.flags}>"
        return msg


class UDP(BasePacket):
    __slots__ = ["src_port", "dst_port", "length", "checksum"]

    def __init__(self, **kwargs):
        super().__init__()
        self.src_port = kwargs.get("src_port", random.randint(34000, 65000))  # 2 bytes  # noqa: E501
        self.dst_port = kwargs.get("dst_port", 53)  # 2 bytes
        self.length = kwargs.get("length", 0)  # 2 bytes
        self.checksum = kwargs.get("checksum", 0)  # 2 bytes

    def __repr__(self):
        return f"<{self.name}| sport={self.src_port}, dport={self.dst_port}>"


class ICMP(BasePacket):
    def __init__(self, **kwargs):
        self.typecode = kwargs.get('typecode', 8)  # 1 byte
        self.subcode = kwargs.get('subcode', 0)  # 1 byte
        self.checksum = kwargs.get('checksum', 0)  # 2 byte
        self.payload = kwargs.get('payload')


class RAW(BasePacket):
    # __slots__ = ["data"]

    def __init__(self, *data):
        super().__init__()
        if len(data) == 1 and type(data) == tuple:
            *data, = data  # if given a single container, it is unpacked
        if not all(map((lambda x: isinstance(x, (str, bytes))), data)):
            msg = f"{self.name} expects data {data} to be either str or bytes."
            raise TypeError(msg)
        data = [i.encode() if isinstance(i, str) else i for i in data]
        self.full_packet = b''.join(data)

    def __truediv__(self, other):
        if isinstance(other, BasePacket):
            return super().__truediv__(other)
        elif isinstance(other, (str, bytes)):
            return self.__class__(self.full_packet, other)
        elif not isinstance(other, object):
            msg = f"{self.name} was not expecting {type(other).__name__}"
            raise errors.InvalidPacketAdditionError(msg)
        print(f"Calling {self.name}.__truediv__")
        return other

    def __rtruediv__(self, other):
        return self.__truediv__(other)

    def __radd__(self, other):
        return self.__truediv__(other)

    def __repr__(self):
        if len(self.full_packet) <= 50:
            return f"<{self.name}| data={self.full_packet.decode()} >"
        return f"<{self.name}| data={self.full_packet.decode():.50}... >"

    def __bytes__(self):
        return self.full_packet
