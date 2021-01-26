from enum import IntFlag
import sys
import ipaddress
import subprocess
import re
import netifaces
import shutil


def ttl_check():
    os = sys.platform.lower()
    if any(map((lambda x: x in os), ["lin", "dar", "os2"])):
        return 64
    elif any(map((lambda x: x in os), ["win", "cyg"])):
        return 128
    else:
        return 254


class Flags(IntFlag):
    """
    URG:  Urgent Pointer field significant
    ACK:  Acknowledgment field significant
    PSH:  Push Function
    RST:  Reset the connection
    SYN:  Synchronize sequence numbers
    FIN:  No more data from sender"""
    FIN = 1 << 0
    SYN = 1 << 1
    RST = 1 << 2
    PSH = 1 << 3
    ACK = 1 << 4
    URG = 1 << 5


flag_dict = {"S": Flags.SYN, "A": Flags.ACK, "F": Flags.FIN, "R": Flags.RST,
             "P": Flags.PSH, "U": Flags.URG, "SYN": Flags.SYN,
             "ACK": Flags.ACK, "FIN": Flags.FIN, "RST": Flags.RST,
             "PSH": Flags.PSH, "URG": Flags.URG}


def combine(*args):
    result = 0
    if len(args) == 1 and type(args[0]) == tuple:
        args = args[0]
    for i in args:
        result |= i
    return result


def flag_check(*flags):
    if all(map((lambda x: isinstance(x, int)), flags)):
        return flags
    result = []
    for i in flags:
        if isinstance(i, int):
            result.append(i)
        elif isinstance(i, str):
            result.append(flag_dict.get(i.upper(), 0))
    return result


def packet_check(args, classobj=None):
    return any(map((lambda x: isinstance(x, classobj)), args))


def _routing_parser(cmd: str, ip_pos: int, net_pos: int, interface_pos: int):
    """Parsers routing table:
       args: ip_pos, ip position
             net_pos, netmask position
             interface_pos, position of interface"""
    a, b, c = ip_pos, net_pos, interface_pos
    routes = []
    for line in subprocess.getoutput(cmd).splitlines():
        line = line.split()
        try:
            if net_pos is not None:
                network = ipaddress.IPv4Network(f"{line[a]}/{line[b]}", False)
            else:
                network = ipaddress.IPv4Network(line[a], False)
            routes.append((network, line[c]))
        except (ValueError, IndexError):
            pass
    return routes


if ttl_check() == 64:
    def routing_info(ip: str):
        if len(subprocess.getoutput("which ip")) != 0:
            result = subprocess.getoutput(f"ip -4 route get {ip}")
            result = re.findall(r'src (.*) u', result)[0]
            try:
                ipaddress.IPv4Address(result)
            except ValueError:
                raise ValueError("Unable to parse IP address.")
        elif len(subprocess.getoutput("which route")) != 0:
            routes = _routing_parser("route -4", 0, 2, -1)
            size = 2**32
            interface = None
            ip = ipaddress.IPv4Address(ip)
            for route in routes:
                if ip in route[0] and size >= route[0].num_addresses:
                    interface = route[1]
                    size = route[0].num_addresses
            if interface is None:
                try:
                    result = netifaces.gateways().get('default', 2).get(2, 2)
                    if result == 2:
                        raise ValueError("Unable to parse IP address.")
                except AttributeError:
                    raise ValueError("Unable to parse IP address.")
            else:
                result = netifaces.ifaddresses(interface).get(2)[0].get('addr')
        elif len(subprocess.getoutput("which netstat -rn")) != 0:
            routes = _routing_parser("netstat -rn", 0, 2, -1)
            size = 2**32
            interface = ''
            ip = ipaddress.IPv4Address(ip)
            for route in routes:
                if ip in route[0] and size >= route[0].num_addresses:
                    interface = route[1]
                    size = route[0].num_addresses
            if len(interface) == 0:
                try:
                    result = netifaces.gateways().get('default', 2).get(2, 2)
                    if result == 2:
                        raise ValueError("Unable to parse IP address.")
                except AttributeError:
                    raise ValueError("Unable to parse IP address.")
            else:
                result = netifaces.ifaddresses(interface).get(2)[0].get('addr')
        else:
            raise ValueError("Unable to parse IP address.")
        return result
elif ttl_check() == 128:
    def routing_info(ip: str):
        size = 2**32
        interface = ''
        if shutil.which("powershell"):
            find = 'powershell.exe -c "get-command {}-netroute"'
            cmd = 'powershell.exe -c "{}"'
            result = []
            if "CommandType" in subprocess.getoutput(find.format("find")):
                cmd = cmd.format(f"(find-netroute {ip}).ipaddress")
                result = subprocess.getoutput(cmd)
            elif "CommandType" in subprocess.getoutput(find.format("get")):
                cmd = cmd.format(f"get-netroute -addressfamily ipv4")
                result = _routing_parser(cmd, 1, None, 0)
                ip = ipaddress.IPv4Address(ip)
                for route in result:
                    if ip in route[0] and size >= route[0].num_addresses:
                        interface = route[1]
                        size = route[0].num_addresses
                if len(interface) == 0:
                    try:
                        result = netifaces.gateways()['default'].get(2, 2)
                        if result == 2:
                            raise ValueError("Unable to parse IP address.")
                    except (AttributeError, IndexError, ValueError):
                        raise ValueError("Unable to parse IP address.")
                else:
                    find = "(Get-NetIPAddress -AddressFamily IPv4 | "
                    find += "Where-Object {$_.InterfaceIndex -eq "
                    find += interface + "}).ipaddress"
                    result = subprocess.getoutput(find)
        elif shutil.which("route"):
            result = _routing_parser("route print -4", 0, 1, -2)
            ip = ipaddress.IPv4Address(ip)
            for route in result:
                if ip in route[0] and size >= route[0].num_addresses:
                    interface = route[1]
                    size = route[0].num_addresses
            if len(interface) != 0:
                result = interface
            else:
                try:
                    result = netifaces.gateways()['default'].get(2, 2)
                    if result == 2:
                        raise ValueError("Unable to parse IP address.")
                except (AttributeError, IndexError, ValueError):
                    raise ValueError("Unable to parse IP address.")
        elif shutil.which("netstat"):
            result = _routing_parser("netstan -rn", 0, 1, -2)
            ip = ipaddress.IPv4Address(ip)
            for route in result:
                if ip in route[0] and size >= route[0].num_addresses:
                    interface = route[1]
                    size = route[0].num_addresses
            if not interface:
                try:
                    result = netifaces.gateways()['default'].get(2, 2)
                    if result == 2:
                        raise ValueError("Unable to parse IP address.")
                except (AttributeError, IndexError, ValueError):
                    raise ValueError("Unable to parse IP address.")
            else:
                result = interface
        else:
            raise ValueError("Unable to parse IP address.")
        return result


def packet_repr(*args):
    ans = ''
    for pkt in args:
        ans += pkt.name + " | "
