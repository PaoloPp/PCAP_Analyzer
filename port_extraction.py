import pandas as pd
import games as g

def extract_unique_ports(input_csv, output_csv):
    """
    Extract all unique ports from the DestinationPort column of a CSV.

    Parameters:
    - input_csv: Path to the input CSV file.
    - output_csv: Path to save the unique ports.
    """
    # Load input CSV
    data = pd.read_csv(input_csv)

    # Extract unique ports from the DestinationPort column
    unique_ports = sorted(data["DestinationPort"].dropna().unique())
    
    # Save unique ports to a new CSV
    pd.DataFrame({"UniquePorts": unique_ports}).to_csv(output_csv, index=False)
    print(f"Unique ports saved to {output_csv}")

def extract_unique_ports_with_ip_filter(input_csv, output_csv, ip_list):
    """
    Extract all unique ports from the DestinationPort column of a CSV,
    filtering rows based on a specified list of IPs.

    Parameters:
    - input_csv: Path to the input CSV file.
    - output_csv: Path to save the unique ports.
    - ip_list: List of IPs to filter on SourceIP or DestinationIP.
    """
    # Load input CSV
    data = pd.read_csv(input_csv)

    # Filter rows where SourceIP matches the IP list
    filtered_data = data[(data['SourceIP'].isin(ip_list))]

    # Extract unique ports from the filtered DestinationPort column
    unique_ports = sorted(filtered_data["DestinationPort"].dropna().unique())
    
    # Save unique ports to a new CSV
    pd.DataFrame({"UniquePorts": unique_ports}).to_csv(output_csv, index=False)
    print(f"Unique ports saved to {output_csv}")

# Example usage
input_csv = "test.csv"
output_csv = "unique_ports.csv"
#extract_unique_ports(input_csv, output_csv)
extract_unique_ports_with_ip_filter(input_csv, output_csv, g.CHESS)
