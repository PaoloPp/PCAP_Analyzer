import pandas as pd
import games as g

def extract_destination_ips(input_csv, source_ip_list, output_csv):
    """
    Extract all unique Destination IPs that a list of Source IPs have communicated with.

    Parameters:
    - input_csv: Path to the input CSV file.
    - source_ip_list: List of Source IPs to filter.
    - output_csv: Path to save the unique Destination IPs.
    """
    # Load the CSV data
    data = pd.read_csv(input_csv)

    # Filter rows where SourceIP is in the given list
    filtered_data = data[data["SourceIP"].isin(source_ip_list)]

    # Extract unique Destination IPs
    unique_dest_ips = filtered_data["DestinationIP"].dropna().unique()

    # Save the Destination IPs to a new CSV
    pd.DataFrame({"DestinationIP": unique_dest_ips}).to_csv(output_csv, index=False)
    print(f"Unique Destination IPs saved to {output_csv}")

# Example Usage
input_csv = "csv/28_06_1000-1330.csv"  # Path to your CSV file
output_csv = "destination_ips.csv"  # Path to the output CSV file

extract_destination_ips(input_csv, g.BRAWLHALLA, "pub_ips_brawlhalla.csv")
extract_destination_ips(input_csv, g.CLASH_ROYALE, "pub_ips_cry.csv")
extract_destination_ips(input_csv, g.EAFC, "pub_ips_eafc.csv")
extract_destination_ips(input_csv, g.ROCKET_LEAGUE, "pub_ips_rocket.csv")
extract_destination_ips(input_csv, g.CHESS, "pub_ips_chess.csv")

#Write a script that given a list of sublists of IPs, substitutes for each IP in the sublist an arbitrary IP for the destinationIP and the dual