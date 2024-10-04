from scapy.all import *
import sys
import os
import constants as c
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


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


if __name__ == "__main__":
    main()
