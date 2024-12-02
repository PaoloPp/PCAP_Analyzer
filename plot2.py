import pandas as pd
import matplotlib.pyplot as plt

def plot_sourceip_destport(csv_file, source_ip, dest_port):
    """
    Plot network data for a specific SourceIP-DestPort pair chronologically with fine time resolution.

    Parameters:
    - csv_file: Path to the CSV file containing network data.
    - source_ip: Source IP to filter by.
    - dest_port: Destination port to filter by.
    """
    # Load CSV data
    df = pd.read_csv(csv_file)

    # Filter data for the given SourceIP-DestPort pair
    filtered_df = df[
        (df["SourceIP"] == source_ip) &
        (df["DestinationPort"] == dest_port)
    ]

    # Convert epoch time to datetime with fine granularity
    filtered_df["FormattedTime"] = pd.to_datetime(filtered_df["Time"], unit="s")

    # Ensure the data is sorted chronologically
    filtered_df = filtered_df.sort_values("FormattedTime")

    # Plot the data
    plt.figure(figsize=(12, 6))
    plt.plot(
        filtered_df["FormattedTime"],
        filtered_df["Length"],
        marker="o",
        linestyle="-",
        label=f"{source_ip} -> DestPort: {dest_port}"
    )

    # Customize x-axis ticks for finer resolution
    plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter("%H:%M:%S.%f"))
    plt.xticks(rotation=45, fontsize=10)

    # Plot settings
    plt.title(f"Chronological Plot for SourceIP: {source_ip} and DestPort: {dest_port}")
    plt.xlabel("Time (hh:mm:ss.ms)")
    plt.ylabel("Packet Length (Bytes)")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()

    # Show the plot
    plt.show()

# Example Usage
csv_file = "28_06_1000-1330.csv"  # Replace with the path to your CSV file
source_ip = "192.168.0.2"  # Replace with the desired SourceIP
dest_port = 9339  # Replace with the desired DestinationPort

plot_sourceip_destport(csv_file, source_ip, dest_port)
