from config import Config
from utils import *

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import time
from datetime import datetime
import sqlite3
import os 
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError, RequestError
from tqdm import tqdm
import csv
import subprocess
import platform



# Loading config file
config = Config()


""" Loading files """

print("####### LOADING FILES #######")

files = [os.path.join(config.dir_input, f) for f in os.listdir(config.dir_input) if (f.endswith(".pcapng") or f.endswith(".pcap"))]

if not files:
    raise FileNotFoundError(f"Aucun fichier pcap trouvé dans {config.dir_input}")


for f in files:
    print(f"File : {f}")

    stop_event = threading.Event()
    t = threading.Thread(target=loading_animation, args=(stop_event,))
    t.start()

    packets = rdpcap(f)


    stop_event.set()
    t.join()

    sys.stdout.write("\n[+] Done       \n")
print("\n")




""" Reading and creating data frame """
data = []
pcap_size = len(packets) 

print("####### READING PACKETS #######")
for idx, pkt in enumerate(packets, start=1):


    progress = (idx/pcap_size) * 100
    if idx % (pcap_size // 100 or 1) == 0:
        progress = (idx / pcap_size) * 100
        bar = '=' * int(progress // 2) + ' ' * (50 - int(progress // 2))
        print(f'\r[{bar}] {progress:.0f}%', end='', flush=True)

    if IP in pkt and (TCP in pkt or UDP in pkt):
        data.append({
            'src_ip': pkt[IP].src,
            'dst_ip': pkt[IP].dst,
            'sport': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            'dport': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            'protocol': pkt[IP].proto,
            'timestamp':  datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")
        })
print("\n")


df = pd.DataFrame(data)

# Cleaning the dataframe (removing packets where both source and destination are public IPs)
df = df[~(df['src_ip'].apply(is_public) & df['dst_ip'].apply(is_public))]




""" Export and creating data frame """

print("####### EXPORTING DATA #######")

path = config.dir_output + datetime.now().strftime("%d-%m-%Y_%H-%M") + "/"
if (config.user_csv or config.user_db or config.user_afterglow):
    os.makedirs(path, exist_ok=True)

# Exporting data to a CSV file
if (config.user_csv):
    
    try: 
        df.to_csv(path + "csv.csv", index=False)
    except:
        print("[-] Error while exporting to csv")
    else:
        print(f"[+] CSV exported to: {path + 'csv.csv'}")


# Exporting data to a SQLite database
if (config.user_db):
        
    try: 
        conn = sqlite3.connect(path + "db.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            src_ip TEXT,
            dst_ip TEXT,
            sport INTEGER,
            dport INTEGER,
            protocol INTEGER,
            timestamp REAL
        )
        """)
        df.to_sql("packets", conn, if_exists="append", index=False)

        conn.commit()
        conn.close()

        print(f"[+] Database exported to: {path + 'db.db'}")

    except:
        print("[-] Error while exporting to database")
        
    finally:
        try:
            if 'conn' in locals():
                conn.close()
        except:
            pass


# Exporting data to Elasticsearch
if (config.user_elastic):
        
    try:
        es = Elasticsearch(config.elastic_url, headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"})
        index_name = "smart_fw_" + datetime.now().strftime("%d-%m-%Y_%H-%M")

        try:
            es.indices.create(
                index=index_name,
                mappings={
                    "properties": {
                        "src_ip": {"type": "ip"},
                        "dst_ip": {"type": "ip"},
                        "sport": {"type": "integer"},
                        "dport": {"type": "integer"},
                        "protocol": {"type": "integer"},
                        "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"}
                    }
                },
                settings={
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                }
            )
            print("[+] Index created successfully")

        except RequestError as e:
                if e.error == 'resource_already_exists_exception':
                    print(f"Index : {index_name}, already exists")
                else:
                    print(f"[-] Error while creating index : {e}")


        helpers.bulk(es, elk_index(df, index_name))
    
    except ConnectionError as e:
        print(f"[-] Connection error to Elasticsearch : {e}")
        print("   [*] Make sure Elasticsearch is running and link to API is correct")

# Rendering with afterglow
if (config.user_afterglow):
    if platform.system() == "Linux":
        
            with open(path + 'csv.csv') as f_in, open(path + "afterglow.csv", "w", newline="") as f_out:
                reader = csv.DictReader(f_in)
                writer = csv.writer(f_out, lineterminator='\n')
                for row in reader:
                    if int(row["dport"]) not in config.tcp_random_range:
                        writer.writerow([row["src_ip"], row["dport"], row["dst_ip"]])   

            subprocess.run([
                "perl", "afterglow.pl", 
                "-i", path + "afterglow.csv",
                "-b", "1",
                "-c", "sample.properties", 
                "-e", "3", 
                "-w", path + "graph.dot" 
            ], check=True)

            subprocess.run([
                "neato", "-Tpng", 
                path + "graph.dot", 
                "-o", path + "graph.png"
            ], check=True)

            print(f"[+] Visualization exported to: {path + 'graph.png'}")

    else:
        print("[-] Afterglow feature only available on Linux")
        
print("\n")     


""" Estimating initial rules """

any_stateful = {}
rules = {}
top_ip = df['dst_ip'].value_counts().index.tolist() # Keeping the list of IPs ranked by number of connections

for ip in top_ip:
    df_dst = df[df['dst_ip'] == ip]
    top_src_for_dst = df_dst.groupby(['src_ip', 'dport', 'protocol']).size().sort_values(ascending=False)
    dst_ip_port = list(top_src_for_dst.index) # Keeping the list of (src_ip, dport, protocol) tuples for the current dst_ip

    # Check if one of the ports is a TCP random port
    has_random_port = any(dport in config.tcp_random_range for _, dport, _ in dst_ip_port)
    
    if ( len(dst_ip_port) > config.max_uniques_ports ) or has_random_port: # Considered as stateful if more than 20 unique (src_ip, dport) pairs are connected to the same dst_ip or TCP random port is used
        continue # any_stateful[ip] = dst_ip_port 
    else:

        df_sub_ip = pd.DataFrame(dst_ip_port, columns=['src_ip', 'dport', 'protocol'])

        # Convert protocols int to names for better readability in the rules
        df_sub_ip['protocol'] = df_sub_ip['protocol'].apply(protocol_to_name)
        dst_ip_port = df_sub_ip.groupby('src_ip')[['dport', 'protocol']].apply(lambda x: list(x.itertuples(index=False, name=None)))

        unique_src_ips = df_dst['src_ip'].unique().tolist()

        # If the destination IP is connected to more than config.public_server_threshold unique source IPs, we consider it as accessible from anyone (any), otherwise we keep the rules with specific source IPs
        if len(unique_src_ips) > config.public_server_threshold:
            any_stateful[ip] = dst_ip_port
        else:
            rules[ip] = dst_ip_port

       


""" Optimizing the rules """

print("####### OPTIMIZING RULES #######")


post_processing_list = []
for ip in rules.keys():
    for src_ip, port_proto_list in rules[ip].items():
        for dport, protocol in port_proto_list:
            post_processing_list.append({
                'dst_ip': ip,
                'src_ip': src_ip,
                'dport': dport,
                'protocol': protocol
            })

post_processing = pd.DataFrame(post_processing_list)
top_port = post_processing[['dport', 'protocol']].value_counts()

# Determine the ports that have more than config.global_port_threshold unique destination IPs, to consider them as accessible from anyone (any)
any_ports = []
if (config.auto_any_rules):

    print("[*] Identifying globally accessible ports")

    for (port, protocol), count in top_port.items():
        df_dst = post_processing[(post_processing['dport'] == port) & (post_processing['protocol'] == protocol)]
        count = int(df_dst['dst_ip'].value_counts().sum())
        if count > config.global_port_threshold:
            any_ports.append((port, protocol))
else:
    any_ports = [(80, 'TCP'), (443, 'TCP'), (53, 'UDP'), (123, 'UDP')] # The user can use a template (HTTP/S, DNS, NTP)

# Filtering rules
if config.remove_same_network:
    print("[*] Removing rules where source and destination IPs are in the same network")

filtered_rules = {}
for dst_ip in rules.keys():
    filtered_rules[dst_ip] = {}
    for src_ip, port_proto_list in rules[dst_ip].items():
        
        # Ensure the rule does not block internal traffic between IPs in the same /24 subnet
        if config.remove_same_network and same_subnet(src_ip, dst_ip):
            continue
        
        # Only keep ports that are not in the any_ports list
        filtered_ports = [(port, proto) for port, proto in port_proto_list if (port, proto) not in any_ports]
        if filtered_ports:  # Ajouter seulement si il reste des ports
            filtered_rules[dst_ip][src_ip] = filtered_ports

# Check if we can group rules with the same source CIDR and same ports

print("[*] Grouping rules by network CIDR")

grouped_rules = {}
for dst_ip in filtered_rules.keys():

    # Keeping CIDR to check for grouping rules with the same source CIDR and same ports
    temp_cidr_groups = {}
    for src_ip, port_proto_list in filtered_rules[dst_ip].items():
        src_cidr = get_network_cidr(src_ip)
        if src_cidr not in temp_cidr_groups:
            temp_cidr_groups[src_cidr] = []
        temp_cidr_groups[src_cidr].append((src_ip, port_proto_list))
    
    grouped_rules[dst_ip] = {}
    for src_cidr, ip_list in temp_cidr_groups.items():
        # If multiple IPs share the same source CIDR, we group them
        if len(ip_list) > 1:

            # Check if they all have the same ports
            all_ports = [set(port_proto_list) for _, port_proto_list in ip_list]

            if all(ports == all_ports[0] for ports in all_ports): # If they have the same ports
                grouped_rules[dst_ip][src_cidr] = sorted(list(all_ports[0]))
            else:
                for src_ip, port_proto_list in ip_list:
                    grouped_rules[dst_ip][src_ip] = port_proto_list # If they don't have the same ports, we keep them separated by IP
        else:
            
            # Only one IP with this CIDR, we keep it separated by IP
            src_ip, port_proto_list = ip_list[0]
            grouped_rules[dst_ip][src_ip] = port_proto_list
print("\n")



""" Generating rules """
print("####### GENERATING RULES #######")
with open(path + "rules.txt", "w", encoding="utf-8") as f:
    f.write(f"# Generated by SmartFireWall on {time.asctime()}\n")
    
    f.write("# Files : ")
    for file in files:
        f.write(f"{file}")
    f.write("\n")

    f.write("\n")

    f.write("# User conf : \n")
    f.write(f"# config.dir_input : {config.dir_input}\n")
    f.write(f"# config.dir_output : {config.dir_output}\n")
    f.write(f"# config.dir_output : {config.dir_output}\n")
    f.write(f"# config.user_csv : {config.user_csv}\n")
    f.write(f"# config.user_db : {config.user_db}\n")
    f.write(f"# config.user_elastic : {config.user_elastic}\n")
    f.write(f"# config.auto_any_rules : {config.auto_any_rules}\n")
    f.write(f"# config.remove_same_network : {config.remove_same_network}\n")
    f.write(f"# config.max_uniques_ports : {config.max_uniques_ports}\n")
    f.write(f"# config.tcp_random_range : {config.tcp_random_range}\n")
    f.write(f"# config.global_port_threshold : {config.global_port_threshold}\n")
    f.write(f"# config.public_server_threshold : {config.public_server_threshold}\n")

    f.write("\n")

    f.write("*filter\n")
    f.write(":INPUT ACCEPT [0:0]\n")
    f.write(":FORWARD ACCEPT [0:0]\n")
    f.write(":OUTPUT ACCEPT [0:0]\n")
    for dst_ip in grouped_rules.keys():
        if grouped_rules[dst_ip]:  

            for src, port_proto_list in grouped_rules[dst_ip].items():
                # Keep TCP and UDP separated
                tcp_ports = sorted([port for port, proto in port_proto_list if proto == 'TCP'])
                udp_ports = sorted([port for port, proto in port_proto_list if proto == 'UDP'])
                
                if tcp_ports and udp_ports:
                    tcp_str = ','.join(map(str, tcp_ports))
                    udp_str = ','.join(map(str, udp_ports))
                    if len(tcp_ports) > 1:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p tcp -m multiport --dports {tcp_str} -j ACCEPT\n")
                    else:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p tcp --dport {tcp_str} -j ACCEPT\n")
                    if len(udp_ports) > 1:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p udp -m multiport --dports {udp_str} -j ACCEPT\n")
                    else:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p udp --dport {udp_str} -j ACCEPT\n")
                elif tcp_ports:
                    tcp_str = ','.join(map(str, tcp_ports))
                    if len(tcp_ports) > 1:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p tcp -m multiport --dports {tcp_str} -j ACCEPT\n")
                    else:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p tcp --dport {tcp_str} -j ACCEPT\n")
                elif udp_ports:
                    udp_str = ','.join(map(str, udp_ports))
                    if len(udp_ports) > 1:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p udp -m multiport --dports {udp_str} -j ACCEPT\n")
                    else:
                        f.write(f"-A INPUT -s {src} -d {dst_ip} -p udp --dport {udp_str} -j ACCEPT\n")

    for dst_ip, src_list in any_stateful.items():
        for src_ip, port_proto_list in src_list.items():
            for dport, protocol in port_proto_list:
                f.write(f"-A INPUT -d {dst_ip} -p {protocol.lower()} --dport {dport} -m state --state NEW,ESTABLISHED -j ACCEPT\n")
                f.write(f"-A INPUT -s {dst_ip} -p {protocol.lower()} --sport {dport} -m state --state ESTABLISHED,RELATED -j ACCEPT\n")

    for port in any_ports:
        f.write(f"-A INPUT -p {port[1].lower()} --sport {port[0]} -m state --state ESTABLISHED,RELATED -j ACCEPT\n")

    f.write("-A INPUT -j DROP\n")
    f.write("COMMIT\n")
    f.write("#Completed on " + time.asctime() + "\n")

print(f"[+] Rules file saved to: {path + 'rules.txt'}")
