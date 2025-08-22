from scapy.all import PcapReader, PcapWriter
import ipaddress
import random
import csv
import pandas as pd
import games as g

def csv_substitute_ip_pairs(input_csv, output_csv, ip_list, substitute_ip):
    """
    Substitutes DestinationIP when SourceIP matches an IP in the list, and vice versa.

    Parameters:
    - input_csv: Path to the input CSV file.
    - output_csv: Path to save the modified CSV file.
    - ip_list: List of IPs to check for substitution.
    - substitute_ip: The IP to substitute when a match is found.
    """
    # Load the CSV data
    data = pd.read_csv(input_csv)

    def replace_ips(row):
        if row["SourceIP"] in ip_list:
            row["DestinationIP"] = substitute_ip
        elif row["DestinationIP"] in ip_list:
            row["SourceIP"] = substitute_ip
        return row

    # Apply substitution
    data = data.apply(replace_ips, axis=1)

    # Save the modified CSV
    data.to_csv(output_csv, index=False)
    print(f"Modified CSV saved to {output_csv}")


def csv_substitute_ips_for_sublists(input_csv, output_csv, ip_sublists_with_subs):
    """
    Substitutes IPs for DestinationIP and SourceIP based on a list of sublists with specific substitution IPs.

    Parameters:
    - input_csv: Path to the input CSV file.
    - output_csv: Path to save the modified CSV file.
    - ip_sublists_with_subs: List of tuples where each tuple contains a sublist of IPs and a substitution IP.
    """
    # Load the CSV data
    data = pd.read_csv(input_csv)

    def replace_ips(row):
        for ip_sublist, substitute_ip in ip_sublists_with_subs:
            if row["SourceIP"] in ip_sublist:
                row["DestinationIP"] = substitute_ip
            elif row["DestinationIP"] in ip_sublist:
                row["SourceIP"] = substitute_ip
        return row

    # Apply substitution
    data = data.apply(replace_ips, axis=1)

    # Save the modified CSV
    data.to_csv(output_csv, index=False)
    print(f"Modified CSV saved to {output_csv}")

def csv_substitute_ips_for_sublists_chunked(input_csv, output_csv, ip_sublists_with_subs, chunksize=10000):
    """
    Substitutes IPs for DestinationIP and SourceIP based on a list of sublists with specific substitution IPs,
    optimized for large files using chunked processing.

    Parameters:
    - input_csv: Path to the input CSV file.
    - output_csv: Path to save the modified CSV file.
    - ip_sublists_with_subs: List of tuples where each tuple contains a sublist of IPs and a substitution IP.
    - chunksize: Number of rows to process per chunk.
    """
    # Flatten sublists and create a mapping dictionary for substitution
    ip_to_substitute = {}
    for ip_sublist, substitute_ip in ip_sublists_with_subs:
        for ip in ip_sublist:
            ip_to_substitute[ip] = substitute_ip

    # Open the output file for writing and process chunks
    with pd.read_csv(input_csv, chunksize=chunksize) as reader, open(output_csv, 'w') as writer:
        for i, chunk in enumerate(reader):
            # Replace DestinationIP if SourceIP is in the sublist
            chunk["DestinationIP"] = chunk.apply(
                lambda row: ip_to_substitute.get(row["SourceIP"], row["DestinationIP"]), axis=1
            )
            # Replace SourceIP if DestinationIP is in the sublist
            chunk["SourceIP"] = chunk.apply(
                lambda row: ip_to_substitute.get(row["DestinationIP"], row["SourceIP"]), axis=1
            )

            # Write chunk to the output file
            chunk.to_csv(writer, index=False, header=(i == 0))  # Write header only for the first chunk
            print(f"Processed chunk {i + 1}")

    print(f"Modified CSV saved to {output_csv}")



def anonymize_ip_by_subnet(input_pcap, output_pcap, tracking_file, ip_groups):
    """
    Anonymizes public IPs in a PCAP file based on a list of private IP groups, assigning public IPs from specified subnets.

    Parameters:
    - input_pcap: Path to the input PCAP file.
    - output_pcap: Path to save the anonymized PCAP file.
    - tracking_file: Path to save the tracking associations.
    - ip_groups: Dictionary where keys are private IP lists and values are subnets for anonymization.
    """
    def is_public_ip(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
        except ValueError:
            return False

    def generate_ip_from_subnet(subnet):
        net = ipaddress.ip_network(subnet)
        return str(net[random.randint(1, net.num_addresses - 2)])

    ip_to_substitute = {}  # Store public-to-anonymized mappings
    tracking_data = set()  # Store unique (PrivateIP, PublicIP, ReplacementIP) tuples

    # Reverse map to quickly find subnets based on private IPs
    private_ip_to_subnet = {}
    for private_ips, subnet in ip_groups.items():
        for ip in private_ips:
            private_ip_to_subnet[ip] = subnet

    with PcapReader(input_pcap) as reader, PcapWriter(output_pcap, append=True, sync=True) as writer:
        for packet in reader:
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst

                # Process SourceIP
                if is_public_ip(src_ip):
                    if src_ip not in ip_to_substitute:
                        replacement_ip = generate_ip_from_subnet(private_ip_to_subnet.get(dst_ip, "10.0.0.0/8"))
                        ip_to_substitute[src_ip] = replacement_ip
                    else:
                        replacement_ip = ip_to_substitute[src_ip]

                    # Track mapping if DestinationIP is in the exception list
                    if dst_ip in private_ip_to_subnet:
                        tracking_data.add((dst_ip, src_ip, replacement_ip))

                    packet["IP"].src = replacement_ip

                # Process DestinationIP
                if is_public_ip(dst_ip):
                    if dst_ip not in ip_to_substitute:
                        replacement_ip = generate_ip_from_subnet(private_ip_to_subnet.get(src_ip, "10.0.0.0/8"))
                        ip_to_substitute[dst_ip] = replacement_ip
                    else:
                        replacement_ip = ip_to_substitute[dst_ip]

                    # Track mapping if SourceIP is in the exception list
                    if src_ip in private_ip_to_subnet:
                        tracking_data.add((src_ip, dst_ip, replacement_ip))

                    packet["IP"].dst = replacement_ip

                # Recalculate checksums
                del packet["IP"].chksum

            writer.write(packet)

    # Save tracking data to the file
    with open(tracking_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["PrivateIP", "PublicIP", "ReplacementIP"])
        writer.writerows(tracking_data)

    print(f"Anonymized PCAP saved to {output_pcap}")
    print(f"Tracking data saved to {tracking_file}")


def anonymize_ip_by_subnet_csv(
    input_csv,
    output_csv,
    tracking_file="ip_replacements.csv",
    ip_groups = [],
    src_col="SourceIP",
    dst_col="DestinationIP",
    default_subnet="10.0.0.0/8"
):
    """
    Anonymizes *public* IPs in a CSV based on private IP groups -> replacement subnets.

    Parameters:
      - input_csv: path to the input CSV file.
      - output_csv: path to write the anonymized CSV.
      - tracking_file: path to write (PrivateIP, PublicIP, ReplacementIP) associations.
      - ip_groups: dict { tuple/list of private IPs : "subnet/CIDR" }
      - src_col, dst_col: column names holding source/destination IPs.
      - default_subnet: fallback subnet if counterpart private IP isn't in ip_groups.
    """
    def is_public_ip(ip):
        if not ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (
                ip_obj.is_private or ip_obj.is_loopback or
                ip_obj.is_reserved or ip_obj.is_link_local or
                getattr(ip_obj, "is_multicast", False)
            )
        except ValueError:
            return False  # not an IP

    def generate_ip_from_subnet(subnet):
        # pick a stable-looking random host from the subnet (avoid network/broadcast for IPv4)
        net = ipaddress.ip_network(subnet, strict=False)
        # For both IPv4/IPv6, avoid first/last if possible
        low = 1 if net.num_addresses > 2 else 0
        high = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses - 1
        host_index = random.randint(low, max(low, high))
        return str(net[host_index])

    # Build reverse map: private_ip -> subnet
    private_ip_to_subnet = {}
    for private_list, subnet in ip_groups.items():
        for pip in private_list:
            private_ip_to_subnet[str(pip)] = subnet

    ip_to_substitute = {}          # public_ip -> anonymized_ip
    tracking_data = set()          # (PrivateIP, PublicIP, ReplacementIP)

    with open(input_csv, newline="") as fin, open(output_csv, "w", newline="") as fout:
        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames or []
        # Ensure src/dst columns exist (will add if missing)
        for col in (src_col, dst_col):
            if col not in fieldnames:
                fieldnames.append(col)

        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            src_ip = row.get(src_col, "") or ""
            dst_ip = row.get(dst_col, "") or ""

            # Process SourceIP (if public)
            if is_public_ip(src_ip):
                if src_ip not in ip_to_substitute:
                    # choose subnet using the counterpart private IP, if any
                    subnet = private_ip_to_subnet.get(dst_ip, default_subnet)
                    ip_to_substitute[src_ip] = generate_ip_from_subnet(subnet)
                replacement_src = ip_to_substitute[src_ip]
                # Track mapping if destination is one of the private IPs
                if dst_ip in private_ip_to_subnet:
                    tracking_data.add((dst_ip, src_ip, replacement_src))
                row[src_col] = replacement_src  # write replacement

            # Process DestinationIP (if public)
            if is_public_ip(dst_ip):
                if dst_ip not in ip_to_substitute:
                    subnet = private_ip_to_subnet.get(src_ip, default_subnet)
                    ip_to_substitute[dst_ip] = generate_ip_from_subnet(subnet)
                replacement_dst = ip_to_substitute[dst_ip]
                # Track mapping if source is one of the private IPs
                if src_ip in private_ip_to_subnet:
                    tracking_data.add((src_ip, dst_ip, replacement_dst))
                row[dst_col] = replacement_dst  # write replacement

            writer.writerow(row)

    # Save tracking data
    with open(tracking_file, "w", newline="") as tf:
        tw = csv.writer(tf)
        tw.writerow(["PrivateIP", "PublicIP", "ReplacementIP"])
        tw.writerows(sorted(tracking_data))

    print(f"Anonymized CSV saved to {output_csv}")
    print(f"Tracking data saved to {tracking_file}")

ip_groups = {
    (
        "192.168.0.2", "192.168.0.13", "192.168.0.25", "192.168.0.29", "192.168.0.33",
        "192.168.0.44", "192.168.0.48", "192.168.0.51"
    ): "10.1.0.0/16", #CLASH_ROYALE
    (
        "192.168.0.4", "192.168.0.8", "192.168.0.9", "192.168.0.11",
        "192.168.0.15", "192.168.0.36", "192.168.0.38", "192.168.0.41"
    ): "10.2.0.0/16", #EAFC
    (
        "192.168.0.10", "192.168.0.19", "192.168.0.47", "192.168.0.49"
    ): "10.3.0.0/16", #BRAWLHALLA
    (
        "192.168.0.5", "192.168.0.39", "192.168.0.42", "192.168.0.50"
    ): "10.4.0.0/16", #ROCKET_LEAGUE
    (
        "192.168.0.3", "192.168.0.18", "192.168.0.23", "192.168.0.24",
        "192.168.0.30", "192.168.0.34", "192.168.0.40", "192.168.0.46"
    ): "10.5.0.0/16", #CHESS
    (
        "192.168.0.6", "192.168.0.14", "192.168.0.16", "192.168.0.27"
    ): "10.6.0.0/16" #MGMT
}


anonymize_ip_by_subnet_csv("metadata_28_06_1000-1330.csv", "anon_metadata_28_06_1000-1330.csv", ip_groups=ip_groups)
#anonymize_ip_by_subnet("PCAP/29_06_1000-1330.pcap","PCAP/anonymized_29_06_1000-1330.pcap","csv/29_06_1000-1330_ip_replacements.csv", ip_groups)
#anonymize_ip_by_subnet("PCAP/29_06_1330-1830.pcap","PCAP/anonymized_29_06_1330-1830.pcap","csv/29_06_1330-1830_ip_replacements.csv", ip_groups)

# Example usage
#ip_sublists_with_subs = [
#    (g.BRAWLHALLA, "10.0.0.1"),
#    (g.CHESS, "10.0.0.2"),
#    (g.CLASH_ROYALE, "10.0.0.3"),
#    (g.EAFC, "10.0.0.4"),
#    (g.ROCKET_LEAGUE, "10.0.0.5"),
#    (g.MGMT, "10.0.0.0")
#] 
#
#substitute_ips_for_sublists_chunked("csv/28_06_1000-1330_metadata.csv", "csv/28_06_1000-1330_metadata_anon.csv", ip_sublists_with_subs)
#
## Example usage
#input_csv = "test.csv"  # Path to the input CSV file
#output_csv = "modified_network_data.csv"  # Path to save the modified CSV
#ip_list =  g.CLASH_ROYALE # List of IPs to match
#substitute_ip = "10.0.0.1"  # The substitution IP
#
#substitute_ip_pairs(input_csv, output_csv, ip_list, substitute_ip)
