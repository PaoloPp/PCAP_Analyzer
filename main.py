from scapy.all import *
import sys
import os
import constants as c
import time
import smtplib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pandas as pd

protocol_mapping = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    27: "RDP",
    132: "SCTP"
}

def main():
    print("Hello World!")
    print("Pcap directory: " + c.PCAP_DIR)
    print("Scapy Version: " + str(scapy.__version__))
    print("Python Version: " + str(sys.version))

def extract_dns_pckt():

    dns_pckt = []

    write_file = PcapWriter(c.PCAP_DIR + "dns_pckts" + ".pcap", append=True)

    for i in range(1,52):

        directory = c.PCAP_DIR + c.IP_PREFIX + str(i) + "/"

        if os.path.isdir(directory):
            for filename in os.listdir(directory):
                f = os.path.join(directory, filename)
                print(f)
                if os.path.isfile(f):
                    try:
                        current_pcap = open_pcap(f)
                    except NameError:
                        print("Error: current_pcap is not defined.")
                    print("Extracting DNS packets from: " + f)
                    for packet in current_pcap:
                        if packet.haslayer(DNS):
                            dns_pckt.append(packet)

    write_file.write(dns_pckt)


def extract_pcap(file_name):    
    start = time.process_time()

    for i in range(1, 256): #21
            current_ip = c.IP_PREFIX + str(i)
            filtered_pckts = []

            try:
                current_cap = open_pcap(file_name)
            except NameError:
                print("Error: current_cap is not defined.")
                
            print("Time taken to open PCAP file: " + str(time.process_time() - start))
            print("Extracting IP: " + c.IP_PREFIX + str(i))

            if not os.path.isdir(c.PCAP_DIR + current_ip):
                os.mkdir(c.PCAP_DIR + current_ip)
            else:
                print("Directory already exists.")

            write_file = PcapWriter(c.PCAP_DIR + current_ip + "/" + current_ip + "_" + file_name, append=True)
            print(write_file)
            for packet in current_cap:
                if packet.haslayer(IP):
                    if packet[IP].src == current_ip or packet[IP].dst == current_ip:
                        print(packet.summary())
                        filtered_pckts.append(packet)
            write_file.write(filtered_pckts)
    
#
#        wrpcap(c.PCAP_DIR + current_ip +
#               "/29_06_1330-1830" + "_" + current_ip + ".pcap",
#               filtered, append=True)


def open_pcap(name):
    print("Opening PCAP file: " + name)
    cap = PcapReader(name)
    return cap



def create_csv(_pcap, output_csv):
    columns = ["Time", "No", "SourceIP", "DestinationIP",
               "SourcePort", "DestinationPort", "SequenceNumber", "AcknowledgementNumber",
               "Protocol", "Length", "Load"]

    # Open output CSV and write headers
    with open(output_csv, 'w') as f:
        pd.DataFrame(columns=columns).to_csv(f, index=False)

    try:
        cap = PcapReader(_pcap)  # Use PcapReader for streaming packets
    except FileNotFoundError:
        print("Error: File not found.")
        return

    pckt_no = 0

    try:
        chunk = []  # Buffer to store rows temporarily
        chunk_size = 1000  # Adjust based on memory
        for pckt in cap:
            pckt_no += 1
            pckt_data = process_pckt(pckt, pckt_no)

            # Ensure no None values and force integers where needed
            pckt_data_clean = {k: int(v) if isinstance(v, (int, float)) and v is not None else v for k, v in pckt_data.items()}
            chunk.append(pckt_data_clean)

            if len(chunk) >= chunk_size:
                # Write chunk to CSV
                write_chunk_to_csv(chunk, output_csv)
                chunk = []  # Clear buffer

            if pckt_no % 10000 == 0:  # Periodic logging
                print(f"Processed {pckt_no} packets")

        # Write remaining packets in the buffer
        if chunk:
            write_chunk_to_csv(chunk, output_csv)
    finally:
        cap.close()  # Ensure file is properly closed


def create_data_csv(_pcap, output_csv):
    columns = ["Time", "Pckt_No", "Data"]

    # Open output CSV and write headers
    with open(output_csv, 'w') as f:
        pd.DataFrame(columns=columns).to_csv(f, index=False)

    try:
        cap = PcapReader(_pcap)  # Use PcapReader for streaming packets
    except FileNotFoundError:
        print("Error: File not found.")
        return

    start = time.process_time()
    pckt_no = 0

    try:
        chunk = []  # Buffer to store rows temporarily
        chunk_size = 1000  # Adjust based on memory
        for pckt in cap:
            pckt_no += 1
            pckt_data = process_data_pckt(pckt, pckt_no)
            chunk.append(pckt_data)

            # Ensure no None values in the packet data
            pckt_data_clean = {k: (v if v is not None else "") for k, v in pckt_data.items()}
            chunk.append(pckt_data_clean)

            if len(chunk) >= chunk_size:
                # Write chunk to CSV
                pd.DataFrame(chunk).to_csv(output_csv, mode='a', index=False, header=False)
                chunk = []  # Clear buffer

            if pckt_no % 10000 == 0:  # Periodic logging
                print(f"Processed {pckt_no} packets")

        # Write remaining packets in the buffer
        if chunk:
            pd.DataFrame(chunk).to_csv(output_csv, mode='a', index=False, header=False)
    finally:
        cap.close()  # Ensure file is properly closed

def process_data_pckt(_pckt, _no):
    pckt_data = {}
    pckt_data = {
        "Time": int(_pckt.time),
        "Pckt_No": _no,
        "Data": base64.b64encode(_pckt["Raw"].load) if _pckt.haslayer('Raw') else None
    }
    return pckt_data

def process_pckt(_pckt, _no):
    pckt_data = {}
    if _pckt.haslayer('TCP'):
        pckt_data = {
            "Time": int(_pckt.time),
            "No": _no,
            "SourceIP": _pckt["IP"].src if _pckt.haslayer('IP') else "",
            "DestinationIP": _pckt["IP"].dst if _pckt.haslayer('IP') else "",
            "SourcePort": int(_pckt["TCP"].sport) if _pckt.haslayer('TCP') else 0,
            "DestinationPort": int(_pckt["TCP"].dport) if _pckt.haslayer('TCP') else 0,
            "SequenceNumber": int(_pckt["TCP"].seq) if _pckt.haslayer('TCP') else 0,
            "AcknowledgementNumber": int(_pckt["TCP"].ack) if _pckt.haslayer('TCP') else 0,
            "Protocol": get_protocol_name(_pckt["IP"].proto) if _pckt.haslayer('IP') else "",
            "Length": int(_pckt["IP"].len) if _pckt.haslayer('IP') else 0,
            "Load": base64.b64encode(_pckt["Raw"].load).decode('utf-8') if _pckt.haslayer('Raw') else ""
        }
    elif _pckt.haslayer('UDP'):
        pckt_data = {
            "Time": int(_pckt.time),
            "No": _no,
            "SourceIP": _pckt["IP"].src if _pckt.haslayer('IP') else "",
            "DestinationIP": _pckt["IP"].dst if _pckt.haslayer('IP') else "",
            "SourcePort": int(_pckt["UDP"].sport) if _pckt.haslayer('UDP') else 0,
            "DestinationPort": int(_pckt["UDP"].dport) if _pckt.haslayer('UDP') else 0,
            "SequenceNumber": 0,  # TCP-only field
            "AcknowledgementNumber": 0,  # TCP-only field
            "Protocol": get_protocol_name(_pckt["IP"].proto) if _pckt.haslayer('IP') else "",
            "Length": int(_pckt["IP"].len) if _pckt.haslayer('IP') else 0,
            "Load": base64.b64encode(_pckt["Raw"].load).decode('utf-8') if _pckt.haslayer('Raw') else ""
        }
    return pckt_data

def write_chunk_to_csv(chunk, output_csv):
    # Write processed chunk to CSV, ensuring integers are written properly
    df = pd.DataFrame(chunk)
    numeric_columns = ["Time", "No", "SourcePort", "DestinationPort", "SequenceNumber", "AcknowledgementNumber", "Length"]
    for col in numeric_columns:
        if col in df.columns:
            df[col] = df[col].fillna(0).astype(int)
    df.to_csv(output_csv, mode='a', index=False, header=False)


def get_protocol_name(protocol_number):
    return protocol_mapping.get(protocol_number, "Unknown")



if __name__ == "__main__":
    main()
