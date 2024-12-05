import pandas as pd
import matplotlib.pyplot as plt

def plot_filtered_sourceip_destport(csv_file, source_ip, dest_port, start_time, end_time):
    """
    Plot network data for a specific SourceIP-DestPort pair within a user-defined time interval,
    aggregating packets by the minute.

    Parameters:
    - csv_file: Path to the CSV file containing network data.
    - source_ip: Source IP to filter by.
    - dest_port: Destination port to filter by.
    - start_time: Start of the time interval (epoch seconds).
    - end_time: End of the time interval (epoch seconds).
    """
    # Load CSV data
    df = pd.read_csv(csv_file)

    # Filter data for the given SourceIP-DestPort pair and time range
    filtered_df = df[
        (df["SourceIP"] == source_ip) &
        (df["DestinationPort"] == dest_port) &
        (df["Time"] >= start_time) &
        (df["Time"] <= end_time)
    ]

    # Convert epoch time to datetime for easier manipulation
    filtered_df["FormattedTime"] = pd.to_datetime(filtered_df["Time"], unit="s")

    # Aggregate packet lengths by minute
    filtered_df.set_index("FormattedTime", inplace=True)
    aggregated_df = filtered_df.resample("10s").sum()["Length"]

    filtered_df.to_csv("filtered.csv", index=False)
    aggregated_df.to_csv("aggregated.csv", index=False)
    # Plot the aggregated data
    plt.figure(figsize=(12, 6))
    plt.plot(
        aggregated_df.index,
        aggregated_df.values,
        marker="o",
        linestyle="-",
        label=f"{source_ip} -> DestPort: {dest_port}"
    )

    # Customize the x-axis
    plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter("%H:%M"))
    plt.xticks(rotation=45, fontsize=10)

    # Plot settings
    plt.title(f"Packet Length Aggregation (by Minute) for {source_ip} -> DestPort: {dest_port}")
    plt.xlabel("Time (hh:mm)")
    plt.ylabel("Total Packet Length (Bytes)")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()

    # Show the plot
    plt.show()

# Example Usage
csv_file = "test.csv"  # Replace with your CSV file path
source_ip = "192.168.0.2"  # Replace with desired SourceIP
dest_port = 9339  # Replace with desired DestinationPort
start_time = 1719561000  # Replace with desired start time in epoch seconds
end_time = 1719583200  # Replace with desired end time in epoch seconds

plot_filtered_sourceip_destport(csv_file, source_ip, dest_port, start_time, end_time)
