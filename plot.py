import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import pytz

def plot_multiple_sourceips_destport(csv_file, source_ips, dest_port, start_time, end_time):
    """
    Plot network data for multiple SourceIP-DestPort pairs within a user-defined time interval,
    aggregating packets by the minute.

    Parameters:
    - csv_file: Path to the CSV file containing network data.
    - source_ips: List of Source IPs to filter by.
    - dest_port: Destination port to filter by.
    - start_time: Start of the time interval (epoch seconds).
    - end_time: End of the time interval (epoch seconds).
    """
    # Load CSV data
    df = pd.read_csv(csv_file)

    # Convert epoch time to datetime for easier manipulation
    df["FormattedTime"] = pd.to_datetime(df["Time"], unit="s").dt.tz_localize("UTC")

    target_tz = pytz.timezone("Etc/GMT-2")
    df["FormattedTime"] = df["FormattedTime"].dt.tz_convert(target_tz)

    # Filter data for the given SourceIP-DestPort pairs and time range
    filtered_df = df[
        (df["SourceIP"].isin(source_ips)) &
        (df["DestinationPort"] == dest_port) &
        (df["Time"] >= start_time) &
        (df["Time"] <= end_time)
    ]

    if filtered_df.empty:
        print("No matching data found for the given criteria.")
        return

    # Aggregate packet lengths by minute
    filtered_df.set_index("FormattedTime", inplace=True)
    aggregated_df = (
        filtered_df.groupby("SourceIP")["Length"]
        .resample("1T")
        .sum()
        .unstack(level=0)
    )

    # Plot the aggregated data for each SourceIP
    plt.figure(figsize=(12, 6))
    for source_ip in source_ips:
        if source_ip in aggregated_df.columns:
            plt.plot(
                aggregated_df.index,
                aggregated_df[source_ip],
                marker="o",
                linestyle="-",
                label=f"SourceIP: {source_ip} -> DestPort: {dest_port}"
            )

    # Customize the x-axis
    ax = plt.gca()
    date_formatter = DateFormatter("%H:%M", tz=target_tz)
    ax.xaxis.set_major_formatter(date_formatter)
    plt.xticks(rotation=45, fontsize=10)

    # Plot settings
    plt.title(f"Packet Length Aggregation (by Minute) for Multiple SourceIPs -> DestPort: {dest_port}")
    plt.xlabel(f"Time (hh:mm) [{"Etc/GMT-2"}]")
    plt.ylabel("Total Packet Length (Bytes)")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()

    # Show the plot
    plt.show()


# Example Usage
csv_file = "28_06_1000-1330.csv"  # Replace with your CSV file path
source_ips = ["192.168.0.2", "192.168.0.13", "192.168.0.25", "192.168.0.29",
              "192.168.0.44", "192.168.0.48", "192.168.0.50", "192.168.0.51"]  # Replace with desired SourceIPs
dest_port = 9339  # Replace with desired DestinationPort
start_time = 1719655200  # Replace with desired start time in epoch seconds
end_time = 1719679600  # Replace with desired end time in epoch seconds

plot_multiple_sourceips_destport(csv_file, source_ips, dest_port, start_time, end_time)
