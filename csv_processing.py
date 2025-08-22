import pandas as pd
import constants as c
import os
import ipaddress
from typing import Iterable, Tuple, List, Dict, Optional

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
# ips_of_interest = [
#     "192.168.0.2",
#     "192.168.0.13",
#     "192.168.0.25",
#     "192.168.0.29",
#     "192.168.0.33",
#     "192.168.0.44",
#     "192.168.0.48",
#     "192.168.0.51"
# ]
# for ip in ips_of_interest:
#     filtered_df = extract_traffic_by_ips(
#         csv_path='csv/game_session/clash_traffic_29_06pm.csv',
#         ip_list=[ip],
#         output_csv=f'csv/game_session/clash_traffic_29_06pm_{ip}.csv',
#         src_col='SourceIP',
#         dst_col='DestinationIP'
#     )
#     print(f"Saved packets for {ip} to 'clash_traffic_29_06pm_{ip}.csv' with {len(filtered_df)} packets.")



def extract_traffic_by_ips(
    csv_path: str,
    ip_items: Iterable[str],
    output_csv: Optional[str] = None,
    per_ip_dir: Optional[str] = None,
    src_col: str = "SourceIP",
    dst_col: str = "DestinationIP",
    chunksize: int = 200_000,
    output_columns: Optional[List[str]] = None,
) -> Dict[str, int]:
    """
    Filter a packet-metadata CSV to rows where either source or destination
    matches a given set of IP addresses and/or CIDR subnets.

    Parameters
    ----------
    csv_path : str
        Path to the input CSV file.
    ip_items : Iterable[str]
        List of IPs and/or CIDR subnets (e.g., ["192.168.0.2","10.0.0.0/8"]).
    output_csv : str, optional
        If provided, path to write the combined filtered CSV.
    per_ip_dir : str, optional
        If provided, writes a separate CSV per *exact IP* encountered,
        named <ip>.csv inside this directory (subnets are not split).
    src_col, dst_col : str
        Column names of source and destination IPs.
    chunksize : int
        Number of rows per chunk to process (memory friendly).
    output_columns : list[str], optional
        If provided, only these columns are written to outputs.

    Returns
    -------
    dict
        Basic stats: {"rows_scanned": int, "rows_matched": int, "distinct_ips_matched": int}
    """
    # Parse inputs into exact IPs and subnets
    exact_ips = set()
    subnets = []
    for item in ip_items:
        item = str(item).strip()
        if not item:
            continue
        if "/" in item:
            subnets.append(ipaddress.ip_network(item, strict=False))
        else:
            exact_ips.add(item)

    def series_in_subnets(s: pd.Series) -> pd.Series:
        """Return boolean Series: True if IP in any subnet (IPv4/IPv6 safe)."""
        if not subnets:
            # No subnet filtering requested—short-circuit False
            return pd.Series(False, index=s.index)
        def in_any(ip):
            try:
                ip_obj = ipaddress.ip_address(ip)
                for net in subnets:
                    if ip_obj in net:
                        return True
            except Exception:
                pass
            return False
        return s.astype(str).apply(in_any)

    # Prepare writers
    header_written_combined = False
    per_ip_writers: Dict[str, Tuple[pd.io.parsers.TextFileReader, bool]] = {}

    if per_ip_dir:
        os.makedirs(per_ip_dir, exist_ok=True)

    rows_scanned = 0
    rows_matched = 0
    ips_seen = set()

    reader = pd.read_csv(csv_path, chunksize=chunksize)
    for chunk in reader:
        rows_scanned += len(chunk)
        # Ensure columns exist
        if src_col not in chunk.columns or dst_col not in chunk.columns:
            raise ValueError(f"Missing columns: {src_col!r} or {dst_col!r} in CSV.")

        # Fast path: exact IPs via vectorized isin
        mask_exact = pd.Series(False, index=chunk.index)
        if exact_ips:
            mask_exact = chunk[src_col].isin(exact_ips) | chunk[dst_col].isin(exact_ips)

        # Subnet path (slower, only applied to rows not already matched)
        if subnets:
            pending = ~mask_exact
            if pending.any():
                sub_src = series_in_subnets(chunk.loc[pending, src_col])
                sub_dst = series_in_subnets(chunk.loc[pending, dst_col])
                mask_sub = pd.Series(False, index=chunk.index)
                mask_sub.loc[pending] = sub_src | sub_dst
                mask = mask_exact | mask_sub
            else:
                mask = mask_exact
        else:
            mask = mask_exact

        filtered = chunk.loc[mask].copy()
        if filtered.empty:
            continue

        # Track stats
        rows_matched += len(filtered)
        ips_seen.update(filtered[src_col].astype(str).unique())
        ips_seen.update(filtered[dst_col].astype(str).unique())

        # Optionally select columns
        if output_columns:
            # Keep only columns that actually exist
            cols = [c for c in output_columns if c in filtered.columns]
            filtered = filtered[cols]

        # Write combined CSV
        if output_csv:
            filtered.to_csv(output_csv, mode="a", index=False, header=not header_written_combined)
            header_written_combined = True

        # Write per-IP CSVs (only for exact IPs for efficiency)
        if per_ip_dir and exact_ips:
            # For each exact IP that appears in this chunk, write those rows
            for ip in exact_ips:
                ip_mask = (filtered[src_col] == ip) | (filtered[dst_col] == ip)
                if not ip_mask.any():
                    continue
                out_path = os.path.join(per_ip_dir, f"{ip}.csv")
                # Write with header if file doesn't exist yet
                write_header = not os.path.exists(out_path)
                filtered.loc[ip_mask].to_csv(out_path, mode="a", index=False, header=write_header)

    return {
        "rows_scanned": rows_scanned,
        "rows_matched": rows_matched,
        "distinct_ips_matched": len(ips_seen),
    }


ips_or_subnets = [
    "192.168.0.2",
    "192.168.0.13",
    "192.168.0.25",
    "192.168.0.29",
    "192.168.0.33",
    "192.168.0.44",
    "192.168.0.48",
    "192.168.0.51",
]
# stats = extract_traffic_by_ips(
#     csv_path="anon_metadata_28_06_1000-1330.csv",
#     ip_items=ips_or_subnets,
#     output_csv="csv/game_session/clash_traffic_28_06am_ms.csv",
#     #per_ip_dir="csv/game_session/per_ip",   # omit if you don't want per-IP files
#     src_col="SourceIP",
#     dst_col="DestinationIP",
#     chunksize=250_000,
#     # output_columns=["Time","SourceIP","DestinationIP","Length","Protocol"],  # optional
# )
# print(stats)

stats = extract_traffic_by_ips(
    csv_path="anon_metadata_28_06_1330-1830.csv",
    ip_items=ips_or_subnets,
    output_csv="csv/game_session/clash_traffic_28_06pm_ms.csv",
    #per_ip_dir="csv/game_session/per_ip",   # omit if you don't want per-IP files
    src_col="SourceIP",
    dst_col="DestinationIP",
    chunksize=250_000,
    # output_columns=["Time","SourceIP","DestinationIP","Length","Protocol"],  # optional
)
print(stats)
stats = extract_traffic_by_ips(
    csv_path="anon_metadata_29_06_1000-1330.csv",
    ip_items=ips_or_subnets,
    output_csv="csv/game_session/clash_traffic_29_06am_ms.csv",
    #per_ip_dir="csv/game_session/per_ip",   # omit if you don't want per-IP files
    src_col="SourceIP",
    dst_col="DestinationIP",
    chunksize=250_000,
    # output_columns=["Time","SourceIP","DestinationIP","Length","Protocol"],  # optional
)
print(stats)
stats = extract_traffic_by_ips(
    csv_path="anon_metadata_29_06_1330-1830.csv",
    ip_items=ips_or_subnets,
    output_csv="csv/game_session/clash_traffic_29_06pm_ms.csv",
    #per_ip_dir="csv/game_session/per_ip",   # omit if you don't want per-IP files
    src_col="SourceIP",
    dst_col="DestinationIP",
    chunksize=250_000,
    # output_columns=["Time","SourceIP","DestinationIP","Length","Protocol"],  # optional
)
print(stats)