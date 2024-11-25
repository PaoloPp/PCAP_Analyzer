from scapy.all import *
import sys
import os
import constants as c
import time
import smtplib
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

def extract_dns_pkt():

    dns_pkt = []

    write_file = PcapWriter(c.PCAP_DIR + "dns_pkts" + ".pcap", append=True)

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
                            dns_pkt.append(packet)

    write_file.write(dns_pkt)


def extract_pcap(file_name):    
    start = time.process_time()

    for i in range(1, 256): #21
            current_ip = c.IP_PREFIX + str(i)
            filtered_pkts = []

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
                        filtered_pkts.append(packet)
            write_file.write(filtered_pkts)
    
#
#        wrpcap(c.PCAP_DIR + current_ip +
#               "/29_06_1330-1830" + "_" + current_ip + ".pcap",
#               filtered, append=True)


def open_pcap(name):
    print("Opening PCAP file: " + name)
    cap = PcapReader(name)
    return cap



def create_csv_(_pcap):
    #pkt["TCP"].time = time -> int() to convert 
    #Number
    #pkt["IP"].src = source
    #pkt["IP"].dst = destination
    #pkt["IP"].proto = protocol ???? #https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    #pkt["IP"].len = length
    #pkt.load = info
    columns = ["Time", "No", "Source", "Destination", "Protocol", "Length", "Load"]
    df = pd.DataFrame(columns=columns)

    try:
        cap = open_pcap(_pcap)
    except NameError:
        print("Error: current_cap is not defined.")
    start = time.process_time()
    pkt_no = 0
    for pckt in cap:
        pkt_no += 1
        pckt_data = process_pckt(pckt)
        print(pkt_no)
        df = pd.concat([df, pd.DataFrame([pckt_data])], ignore_index=True)

    
    df.to_csv("test.csv", index=False)
    print("Packet information saved to packets_info.csv")
    print("Time taken to process packets: " + str(time.process_time() - start))

def create_csv2(_pcap):

    columns = ["Time", "No", "SourceIP", "DestinationIP", "Protocol", "Length", "Load"]
    packet_data_list = []  # List to store packet data

    try:
        cap = open_pcap(_pcap)
    except NameError:
        print("Error: open_pcap function is not defined.")
        return

    start = time.process_time()
    pkt_no = 0

    for pckt in cap:
        pkt_no += 1
        pckt_data = process_pckt(pckt)  # Function to process individual packets
        pckt_data["No"] = pkt_no  # Add packet number to the data
        packet_data_list.append(pckt_data)  # Collect packet data in the list
        print(pkt_no)

    # Create the DataFrame after collecting all data
    df = pd.DataFrame(packet_data_list, columns=columns)
    df.to_csv("test.csv", index=False)

    print(f"Processing time: {time.process_time() - start:.2f}s")
    return df


def process_pckt(_pckt):
    pckt_data = {
        "Time": _pckt.time,
        "No": "",
        "SourceIP": _pckt["IP"].src if _pckt.haslayer('IP') else None,
        "DestinationIP": _pckt["IP"].dst if _pckt.haslayer('IP') else None,
        "Protocol": get_protocol_name(_pckt["IP"].proto) if _pckt.haslayer('IP') else None,
        "Length": _pckt["IP"].len if _pckt.haslayer('IP') else None,
        "Load": _pckt["Raw"].load if _pckt.haslayer('Raw') else None
    }
    print(pckt_data)
    return pckt_data

def get_protocol_name(protocol_number):
    return protocol_mapping.get(protocol_number, "Unknown")



if __name__ == "__main__":
    main()
