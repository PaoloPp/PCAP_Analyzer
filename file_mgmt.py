from scapy.all import PcapReader

def open_pcap(name):
    print("Opening PCAP file: " + name)
    try:
        cap = PcapReader(name)
    except NameError:
        print("Error: current_cap is not defined.")
    return cap