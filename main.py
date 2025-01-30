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

if __name__ == "__main__":
    main()
