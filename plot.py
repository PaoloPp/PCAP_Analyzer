import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import pytz
from datetime import datetime
import constants as c
import os

def plot_top_associations(input_csv, associations_csv, start_time, end_time):
    """
    Plot network data for the top 5 associations chronologically within a user-defined time interval,
    aggregating packets by the minute.

    Parameters:
    - input_csv: Path to the CSV file containing network data.
    - associations_csv: Path to the CSV file with sorted associations.
    - start_time: Start of the time interval (epoch seconds).
    - end_time: End of the time interval (epoch seconds).
    """
    # Load network data
    df = pd.read_csv(input_csv)

    # Load the sorted associations and take the top 5
    associations_df = pd.read_csv(associations_csv).head(5)

    print(associations_df.columns)

    # Convert epoch time to datetime
    df["FormattedTime"] = pd.to_datetime(df["Time"], unit="s")

    # Set up the plot
    plt.figure(figsize=(14, 8))

    # Iterate over the top associations and plot data
    for _, row in associations_df.iterrows():
        source_ip = row["SourceIP"]
        dest_ip = row["DestinationIP"]
        source_port = row["SourcePort"]
        dest_port = row["DestinationPort"]

        # Filter the data for the specific association and time range
        filtered_df = df[
            (df["SourceIP"] == source_ip) &
            (df["DestinationIP"] == dest_ip) &
            (df["SourcePort"] == source_port) &
            (df["DestinationPort"] == dest_port) &
            (df["Time"] >= start_time) &
            (df["Time"] <= end_time)
        ]

        # Aggregate packet lengths by minute
        filtered_df.set_index("FormattedTime", inplace=True)
        aggregated_df = filtered_df.resample("1min").sum()["Length"]

        # Plot the aggregated data
        plt.plot(
            aggregated_df.index,
            aggregated_df.values,
            marker="o",
            linestyle="-",
            label=f"{source_ip}:{source_port} -> {dest_ip}:{dest_port}"
        )

    # Customize the x-axis
    plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter("%H:%M"))
    plt.xticks(rotation=45, fontsize=10)

    # Plot settings
    plt.title("Packet Length Aggregation (by Minute) for Top Associations")
    plt.xlabel("Time (hh:mm)")
    plt.ylabel("Total Packet Length (Bytes)")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()

    save_plot(plt)
    
    # Show the plot
    plt.show()

# Example Usage
input_csv = "test.csv"  # Replace with your network data CSV file
associations_csv = "sorted_associations.csv"  # Replace with your sorted associations CSV file
start_time = 1719561000  # Replace with desired start time in epoch seconds
end_time = 1719583200  # Replace with desired end time in epoch seconds

def plot_multiple_sourceips_destport(csv_file, source_ips, dest_port, source_port, start_time, end_time):
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
    filtered_df_out = df[
        (df["SourceIP"].isin(source_ips)) &
        (df["DestinationPort"] == dest_port) &
        (df["Time"] >= start_time) &
        (df["Time"] <= end_time)
    ]

    filtered_df_in = df[
        (df["DestinationIP"].isin(source_ips)) &
        (df["SourcePort"] == dest_port) &
        (df["Time"] >= start_time) &
        (df["Time"] <= end_time)
    ]

    if filtered_df_out.empty:
        print("No matching data found for the given criteria.")
        return
    
    if filtered_df_in.empty:
        print("No matching data found for the given criteria.")
        return

    # Aggregate packet lengths by minute
    filtered_df_out.set_index("FormattedTime", inplace=True)
    aggregated_df_out = (
        filtered_df_out.groupby("SourceIP")["Length"]
        .resample("1min")
        .sum()
        .unstack(level=0)
    )

    filtered_df_in.set_index("FormattedTime", inplace=True)
    aggregated_df_in = (
        filtered_df_in.groupby("DestinationIP")["Length"]
        .resample("1min")
        .sum()
        .unstack(level=0)
    )

    # Plot the aggregated data for each SourceIP
    plt.figure(figsize=(12, 6))
    for source_ip in source_ips:
        if source_ip in aggregated_df_out.columns:
            plt.plot(
                aggregated_df_out.index,
                aggregated_df_out[source_ip],
                marker="o",
                linestyle="-",
                label=f"SourceIP: {source_ip} -> DestPort: {dest_port}"
            )
    for destination_ip in destination_ips:
        if destination_ip in aggregated_df_in.columns:
            plt.plot(
                aggregated_df_in.index,
                aggregated_df_in[destination_ip],
                marker="o",
                linestyle="-",
                label=f"DestinationIP: {destination_ip} <- DestPort: {source_port}"
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

    save_plot(plt)

    # Show the plot
    plt.show()

def save_plot(_plt):
    os.makedirs(c.PCAP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(c.PCAP_DIR, f"plot_{timestamp}.png")
    _plt.savefig(output_file)
    print(f"Plot saved to {output_file}")

# Example Usage
#csv_file = "csv/28_06_1000-1330.csv"  # Replace with your CSV file path
csv_file = "test.csv"
#source_ips = ["192.168.0.2", "192.168.0.13", "192.168.0.25", "192.168.0.29",
#              "192.168.0.44", "192.168.0.48", "192.168.0.50", "192.168.0.51"]  # Replace with desired SourceIPs
source_ips = ["192.168.0.2"]
destination_ips = source_ips
dest_port = 9339  # Replace with desired DestinationPort
source_port = dest_port
start_time = 1719561600  # Replace with desired start time in epoch seconds
end_time = 1719567310  # Replace with desired end time in epoch seconds

plot_multiple_sourceips_destport(csv_file, source_ips, dest_port, source_port, start_time, end_time)
