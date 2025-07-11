import pandas as pd
import constants as c

def extract_traffic_by_ips(csv_path, ip_list, output_csv,
                           src_col='Source', dst_col='Destination'):
    """
    Reads a packet-metadata CSV and filters to only those rows where
    the source or destination IP is in ip_list, then saves the result.

    Parameters
    ----------
    csv_path : str
        Path to the input CSV file.
    ip_list : list of str
        List of IP addresses to filter on.
    output_csv : str
        Path where the filtered results will be written as CSV.
    src_col : str, optional
        Name of the source-IP column in the CSV (default 'Source').
    dst_col : str, optional
        Name of the destination-IP column in the CSV (default 'Destination').

    Returns
    -------
    pandas.DataFrame
        The filtered DataFrame of packets involving any IP in ip_list.
    """
    # Load the data
    df = pd.read_csv(csv_path)

    # Filter rows where either source or destination matches
    mask = df[src_col].isin(ip_list) | df[dst_col].isin(ip_list)
    filtered = df.loc[mask].copy()

    # Save to CSV
    filtered.to_csv(output_csv, index=False)

    return filtered

# Example usage
ips_of_interest = [
    "192.168.0.2",
    "192.168.0.13",
    "192.168.0.25",
    "192.168.0.29",
    "192.168.0.33",
    "192.168.0.44",
    "192.168.0.48",
    "192.168.0.51"
]
for ip in ips_of_interest:
    filtered_df = extract_traffic_by_ips(
        csv_path='csv/game_session/clash_traffic_29_06pm.csv',
        ip_list=[ip],
        output_csv=f'csv/game_session/clash_traffic_29_06pm_{ip}.csv',
        src_col='SourceIP',
        dst_col='DestinationIP'
    )
    print(f"Saved packets for {ip} to 'clash_traffic_29_06pm_{ip}.csv' with {len(filtered_df)} packets.")
