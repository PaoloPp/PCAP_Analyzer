import pandas as pd
import games as g

def substitute_ip_pairs(input_csv, output_csv, ip_list, substitute_ip):
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


def substitute_ips_for_sublists(input_csv, output_csv, ip_sublists_with_subs):
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

# Example usage
input_csv = "test.csv"  # Path to the input CSV file
output_csv = "modified_network_data.csv"  # Path to save the modified CSV
ip_sublists_with_subs = [
    (g.BRAWLHALLA, "10.0.0.1"),
    (g.CHESS, "10.0.0.2"),
    (g.CLASH_ROYALE, "10.0.0.3"),
    (g.EAFC, "10.0.0.4"),
    (g.ROCKET_LEAGUE, "10.0.0.5"),
    (g.MGMT, "10.0.0.0")
] 

substitute_ips_for_sublists(input_csv, output_csv, ip_sublists_with_subs)
#
## Example usage
#input_csv = "test.csv"  # Path to the input CSV file
#output_csv = "modified_network_data.csv"  # Path to save the modified CSV
#ip_list =  g.CLASH_ROYALE # List of IPs to match
#substitute_ip = "10.0.0.1"  # The substitution IP
#
#substitute_ip_pairs(input_csv, output_csv, ip_list, substitute_ip)
