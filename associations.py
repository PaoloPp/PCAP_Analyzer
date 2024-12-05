import pandas as pd

def create_association_csv(input_csv, output_csv):
    """
    Create a new CSV with unique associations of SourceIP, DestinationIP, SourcePort, and DestinationPort,
    along with the count of packets for each association, sorted by descending PacketCount.

    Parameters:
    - input_csv: Path to the input CSV file.
    - output_csv: Path to save the output CSV file.
    """
    # Load the CSV data
    df = pd.read_csv(input_csv)

    # Group by the unique association columns and count the number of packets in each group
    association_counts = (
        df.groupby(["SourceIP", "DestinationIP", "SourcePort", "DestinationPort"])
        .size()
        .reset_index(name="PacketCount")
    )

    # Sort by descending PacketCount
    sorted_associations = association_counts.sort_values(by="PacketCount", ascending=False)

    # Save the result to a new CSV
    sorted_associations.to_csv(output_csv, index=False)
    print(f"Sorted association CSV saved to '{output_csv}'.")

# Example usage
input_csv = "test.csv"  # Replace with your input CSV file path
output_csv = "sorted_associations.csv"  # Replace with your desired output CSV file path
create_association_csv(input_csv, output_csv)
