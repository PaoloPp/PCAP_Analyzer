from port_extraction import *
from pcap_processing import *
from data_model import *
import sys
import constants as c

def main():
    print("Hello World!")
    print("Pcap directory: " + c.PCAP_DIR)
    print("Scapy Version: " + str(scapy.__version__))
    print("Python Version: " + str(sys.version))

    #create_data_payload_csv(c.PCAP_DIR + "28_06_1000-1330.pcap",
    #                        c.CSV_DIR + "28_06_1000-1330_metadata.csv",
    #                        c.CSV_DIR + "28_06_1000-1330_payload.csv")
    
    #create_data_payload_csv(c.PCAP_DIR + "28_06_1330-1830.pcap",
    #                        c.CSV_DIR + "28_06_1330-1830_metadata.csv",
    #                        c.CSV_DIR + "28_06_1330-1830_payload.csv")
    #
    #create_data_payload_csv(c.PCAP_DIR + "29_06_1330-1830.pcap",
    #                        c.CSV_DIR + "29_06_1330-1830_metadata.csv",
    #                        c.CSV_DIR + "29_06_1330-1830_payload.csv")
    #
    #create_data_payload_csv(c.PCAP_DIR + "29_06_1000-1330.pcap",
    #                        c.CSV_DIR + "29_06_1000-1330_metadata.csv",
    #                        c.CSV_DIR + "29_06_1000-1330_payload.csv")

if __name__ == "__main__":
    main()
