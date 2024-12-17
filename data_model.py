import pandas as pd
import file_mgmt as fm
from packet_processing import *

def create_csv(_pcap, output_csv):
    columns = ["Time", "No", "SourceIP", "DestinationIP",
               "SourcePort", "DestinationPort", "SequenceNumber", "AcknowledgementNumber",
               "Protocol", "Length", "Load"]

    # Open output CSV and write headers
    with open(output_csv, 'w') as f:
        pd.DataFrame(columns=columns).to_csv(f, index=False)

    cap = fm.open_pcap(_pcap)

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

    cap = fm.open_pcap(_pcap)

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


def create_data_payload_csv(_pcap, _metadata_csv, _payload_csv):
    metadata_columns = [
        "Time", "No", "SourceIP", "DestinationIP", 
        "SourcePort", "DestinationPort", "SequenceNumber", 
        "AcknowledgementNumber", "Protocol", "Length"
    ]
    payload_columns = ["No", "Length", "Payload"]

    # Open output CSV and write headers
    with open(_metadata_csv, 'w') as f:
        pd.DataFrame(columns=metadata_columns).to_csv(f, index=False)

    with open(_payload_csv, 'w') as f:
        pd.DataFrame(columns=payload_columns).to_csv(f, index=False)


    cap = fm.open_pcap(_pcap)

    pckt_no = 0

    try:
        metadata_chunk = []  # Buffer to store rows temporarily
        payload_chunk = []  
        chunk_size = 1000  # Adjust based on memory
        for pckt in cap:
            pckt_no += 1
            pckt_metadata, pckt_payload = process_metadata_payload(pckt, pckt_no)

            # Ensure no None values and force integers where needed
            pckt_metadata_clean = {k: int(v) if isinstance(v, (int, float)) and v is not None else v for k, v in pckt_metadata.items()}
            pckt_payload_clean = {k: int(v) if isinstance(v, (int, float)) and v is not None else v for k, v in pckt_payload.items()}

            metadata_chunk.append(pckt_metadata_clean)
            payload_chunk.append(pckt_payload_clean)

            if len(metadata_chunk) >= chunk_size:
                # Write chunk to CSV
                write_chunk_to_csv(metadata_chunk, _metadata_csv)
                metadata_chunk = []  # Clear buffer

            if len(payload_chunk) >= chunk_size:
                # Write chunk to CSV
                write_chunk_to_csv(payload_chunk, _payload_csv)
                payload_chunk = []  # Clear buffer

            if pckt_no % 10000 == 0:  # Periodic logging
                print(f"Processed {pckt_no} packets")

        # Write remaining packets in the buffer
        if metadata_chunk:
            write_chunk_to_csv(metadata_chunk, _metadata_csv)
        if payload_chunk:
            write_chunk_to_csv(payload_chunk, _payload_csv)

    finally:
        cap.close()  # Ensure file is properly closed



def write_chunk_to_csv(chunk, output_csv):
    # Write processed chunk to CSV, ensuring integers are written properly
    df = pd.DataFrame(chunk)
    numeric_columns = ["Time", "No", "SourcePort", "DestinationPort", "SequenceNumber", "AcknowledgementNumber", "Length"]
    for col in numeric_columns:
        if col in df.columns:
            df[col] = df[col].fillna(0).astype(int)
    df.to_csv(output_csv, mode='a', index=False, header=False)