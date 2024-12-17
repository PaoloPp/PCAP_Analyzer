from scapy.all import *
import os
import time
import constants as c
import file_mgmt as fm



def extract_pcap(file_name):    
    start = time.process_time()

    for i in range(1, 256): #21
            current_ip = c.IP_PREFIX + str(i)
            filtered_pckts = []

            current_cap = fm.open_pcap(file_name)
                
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
                    current_pcap = fm.open_pcap(f)
                    print("Extracting DNS packets from: " + f)
                    for packet in current_pcap:
                        if packet.haslayer(DNS):
                            dns_pckt.append(packet)
                            
    write_file.write(dns_pckt)