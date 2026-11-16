"""Read assigned Linux interface addresses without root, shell commands or DNS lookups."""
from functools import lru_cache
import ipaddress
from pathlib import Path
import socket
import struct
import time


def normalize(value):
    value=str(value).split('%',1)[0]
    address=ipaddress.ip_address(value)
    return str(address.ipv4_mapped or address) if address.version==6 else str(address)


def _netlink_addresses():
    result=set();sequence=time.monotonic_ns()&0xffffffff
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as connection:
        connection.settimeout(1);connection.bind((0,0))
        connection.sendto(struct.pack('=IHHII',24,22,0x301,sequence,0)+struct.pack('=BBBBI',socket.AF_UNSPEC,0,0,0,0),(0,0))
        for _ in range(128):
            packet=connection.recv(65536);offset=0
            while offset+16<=len(packet):
                length,kind,flags,seq,pid=struct.unpack_from('=IHHII',packet,offset)
                if length<16 or offset+length>len(packet):raise OSError('Invalid interface response')
                body=packet[offset+16:offset+length];offset+=(length+3)&~3
                if seq!=sequence:continue
                if kind==3:return result
                if kind==2:
                    error=struct.unpack_from('=i',body)[0]
                    if error:raise OSError(-error,'Interface query failed')
                    continue
                if kind!=20 or len(body)<8:continue
                family=body[0]
                if family not in (socket.AF_INET,socket.AF_INET6):continue
                attrs={};position=8
                while position+4<=len(body):
                    size,attribute=struct.unpack_from('=HH',body,position)
                    if size<4 or position+size>len(body):raise OSError('Invalid address attribute')
                    attrs[attribute]=body[position+4:position+size];position+=(size+3)&~3
                raw=attrs.get(2,attrs.get(1))  # IFA_LOCAL, or IFA_ADDRESS (IPv6)
                expected=4 if family==socket.AF_INET else 16
                if raw is not None and len(raw)>=expected:result.add(normalize(socket.inet_ntop(family,raw[:expected])))
    raise OSError('Incomplete interface response')


def _fallback_addresses():
    result={'127.0.0.1','::1'}
    import fcntl
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
        for _,name in socket.if_nameindex():
            try:
                raw=fcntl.ioctl(connection.fileno(),0x8915,struct.pack('256s',name.encode()[:15]))
                result.add(socket.inet_ntoa(raw[20:24]))
            except OSError:continue
    try:
        for line in Path('/proc/net/if_inet6').read_text().splitlines():result.add(str(ipaddress.IPv6Address(bytes.fromhex(line.split()[0]))))
    except OSError:pass
    return result


@lru_cache(maxsize=2)
def _snapshot(bucket):
    try:addresses=_netlink_addresses()
    except (OSError,AttributeError):
        try:addresses=_fallback_addresses()
        except OSError:addresses={'127.0.0.1','::1'}
    addresses.update(('127.0.0.1','::1'))
    hostname=socket.gethostname().lower().rstrip('.')
    return frozenset(addresses),frozenset(('localhost',hostname,hostname.split('.')[0]))


def local_addresses():return _snapshot(int(time.monotonic()//5))[0]


def local_host(host):
    if host is None:return False
    try:return normalize(host) in local_addresses()
    except ValueError:return host.lower().rstrip('.') in _snapshot(int(time.monotonic()//5))[1]


def urls(port,bind='0.0.0.0'):
    result=[]
    for value in sorted(local_addresses()):
        address=ipaddress.ip_address(value)
        if address.is_unspecified or address.is_link_local:continue
        if bind=='0.0.0.0' and address.version!=4:continue
        if bind not in ('0.0.0.0','::') and normalize(bind)!=value:continue
        result.append('http://'+('['+value+']' if address.version==6 else value)+':'+str(port))
    return result
