from port_extraction import *
from pcap_processing import *
from data_model import *
from anonymization import *
import sys
import constants as c

def main():
    print("Hello World!")
    print("Pcap directory: " + c.PCAP_DIR)
    print("Scapy Version: " + str(scapy.__version__))
    print("Python Version: " + str(sys.version))

    #create_metadata_csv("PCAP/28_06_1000-1330.pcap", "metadata_28_06_1000-1330.csv", 99999999999999)
    create_metadata_csv("PCAP/28_06_1330-1830.pcap", "metadata_28_06_1330-1830.csv", 99999999999999)
    create_metadata_csv("PCAP/29_06_1000-1330.pcap", "metadata_29_06_1000-1330.csv", 99999999999999)
    create_metadata_csv("PCAP/29_06_1330-1830.pcap", "metadata_29_06_1330-1830.csv", 99999999999999)

    #anonymize_ip_by_subnet_csv("metadata_28_06_1000-1330.csv", "anon_metadata_28_06_1000-1330.csv", ip_groups=ip_groups)
    anonymize_ip_by_subnet_csv("metadata_28_06_1330-1830.csv", "anon_metadata_28_06_1330-1830.csv", ip_groups=ip_groups)
    anonymize_ip_by_subnet_csv("metadata_29_06_1000-1330.csv", "anon_metadata_29_06_1000-1330.csv", ip_groups=ip_groups)
    anonymize_ip_by_subnet_csv("metadata_29_06_1330-1830.csv", "anon_metadata_29_06_1330-1830.csv", ip_groups=ip_groups)


    

if __name__ == "__main__":
    main()
