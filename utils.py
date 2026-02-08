import ipaddress
import sys
import time
import threading

def loading_animation(stop_event):
    dots = ["   ", ".  ", ".. ", "..."]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write("\r[*] Loading" + dots[i % len(dots)])
        sys.stdout.flush()
        time.sleep(0.4)
        i += 1

def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def same_subnet(ip1, ip2):
    try:
        net1 = ipaddress.ip_network(f"{ip1}/24", strict=False)
        net2 = ipaddress.ip_network(f"{ip2}/24", strict=False)
        return net1 == net2
    except ValueError:
        return False

def get_network_cidr(ip):
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return ip

def protocol_to_name(proto):
    if proto == 6 or proto == '6':
        return 'TCP'
    elif proto == 17 or proto == '17':
        return 'UDP'
    else:
        return str(proto)


def elk_index(df, index_name):
    for index, row in df.iterrows():
        yield{
            "_index": index_name,
            "_source": row.to_dict()
        }