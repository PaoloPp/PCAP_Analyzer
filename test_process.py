import pandas as pd
import base64
from scapy.all import PcapReader

def create_data_and_payload_csv(pcap_file, metadata_csv, payload_csv):
    """
    Process a PCAP file to generate two CSVs:
    - metadata_csv: Contains all fields except the payload.
    - payload_csv: Contains payload data with corresponding packet indices.

    Parameters:
    - pcap_file: Path to the PCAP file.
    - metadata_csv: Path to the output metadata CSV file.
    - payload_csv: Path to the output payload CSV file.
    """
    

    # Initialize empty DataFrames for metadata and payload
    metadata_df = pd.DataFrame(columns=metadata_columns)
    payload_df = pd.DataFrame(columns=payload_columns)

    try:
        cap = PcapReader(pcap_file)
    except FileNotFoundError:
        print(f"Error: PCAP file '{pcap_file}' not found.")
        return

    packet_no = 0
    try:
        for packet in cap:
            packet_no += 1

            # Extract metadata and payload
            metadata, payload = process_pckt(packet, packet_no)

            # Append metadata and payload to respective lists
            metadata_df = pd.concat([metadata_df, pd.DataFrame([metadata])], ignore_index=True)
            if payload:
                payload_df = pd.concat([payload_df, pd.DataFrame([{"No": packet_no, "Payload": payload}])], ignore_index=True)

            if packet_no % 1000 == 0:  # Periodic logging
                print(f"Processed {packet_no} packets...")

        # Save metadata and payload data to CSV
        metadata_df.to_csv(metadata_csv, index=False)
        payload_df.to_csv(payload_csv, index=False)

        print(f"Metadata saved to '{metadata_csv}', Payload saved to '{payload_csv}'")
    finally:
        cap.close()

def process_pckt(packet, packet_no):
    """
    Process a single packet to extract metadata and payload.

    Parameters:
    - packet: The packet to process.
    - packet_no: The current packet number.

    Returns:
    - metadata: Dictionary of packet metadata.
    - payload: Base64-encoded payload or None if no payload.
    """
    metadata = {
        "Time": int(packet.time),
        "No": packet_no,
        "SourceIP": packet["IP"].src if packet.haslayer("IP") else "",
        "DestinationIP": packet["IP"].dst if packet.haslayer("IP") else "",
        "SourcePort": int(packet["TCP"].sport) if packet.haslayer("TCP") else (int(packet["UDP"].sport) if packet.haslayer("UDP") else 0),
        "DestinationPort": int(packet["TCP"].dport) if packet.haslayer("TCP") else (int(packet["UDP"].dport) if packet.haslayer("UDP") else 0),
        "SequenceNumber": int(packet["TCP"].seq) if packet.haslayer("TCP") else 0,
        "AcknowledgementNumber": int(packet["TCP"].ack) if packet.haslayer("TCP") else 0,
        "Protocol": "TCP" if packet.haslayer("TCP") else ("UDP" if packet.haslayer("UDP") else ""),
        "Length": int(packet["IP"].len) if packet.haslayer("IP") else 0
    }
    payload = None
    if packet.haslayer("Raw"):
        payload = base64.b64encode(bytes(packet["Raw"].load)).decode("utf-8")
    return metadata, payload

# Example Usage
pcap_file = "PCAP/192.168.0.2/192.168.0.2_28_06_1000-1330.pcap"  # Replace with your PCAP file path
metadata_csv = "metadata.csv"       # Desired output for metadata
payload_csv = "payload.csv"         # Desired output for payloads

create_data_and_payload_csv(pcap_file, metadata_csv, payload_csv)
