import pandas as pd
import matplotlib.pyplot as plt

def plot_temporal_data_for_source(csv_file, source_ip):
    # Read the CSV file
    df = pd.read_csv(csv_file)

    # Filter data for the given SourceIP
    df = df[df["SourceIP"] == source_ip]

    # Ensure data is sorted by time for temporal plotting
    df = df.sort_values("Time")

    # Group by DestinationIP, SourcePort, and DestinationPort
    grouped = df.groupby(["DestinationIP", "SourcePort", "DestinationPort"])

    # Create a plot for each group
    plt.figure(figsize=(10, 6))
    #for (dst_ip, src_port, dst_port), group in grouped:
    #    plt.plot(group["Time"], group["Length"], label=f"{source_ip}:{src_port} -> {dst_ip}:{dst_port}")

    # Plot settings
    plt.title(f"Temporal Plot for SourceIP: {source_ip}")
    plt.xlabel("Time")
    plt.ylabel("Packet Length")
    plt.legend(loc="best", fontsize="small")
    plt.grid(True)
    plt.tight_layout()

    # Show the plot
    plt.show()

# Example usage
csv_file = "test.csv"  # Replace with your CSV file path
source_ip = "192.168.0.2"  # Replace with the desired SourceIP
plot_temporal_data_for_source(csv_file, source_ip)
