import pandas as pd
import matplotlib.pyplot as plt

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

    # Show the plot
    plt.show()

# Example Usage
input_csv = "test.csv"  # Replace with your network data CSV file
associations_csv = "sorted_associations.csv"  # Replace with your sorted associations CSV file
start_time = 1719561000  # Replace with desired start time in epoch seconds
end_time = 1719583200  # Replace with desired end time in epoch seconds

plot_top_associations(input_csv, associations_csv, start_time, end_time)
