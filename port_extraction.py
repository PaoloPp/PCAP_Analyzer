import pandas as pd

def extract_unique_ports(input_csv, output_csv):
    """
    Extract all unique ports from the DestinationPort column of a CSV.

    Parameters:
    - input_csv: Path to the input CSV file.
    - output_csv: Path to save the unique ports.
    """
    # Load input CSV
    data = pd.read_csv(input_csv)

    # Extract unique ports from the DestinationPort column
    unique_ports = sorted(data["DestinationPort"].dropna().unique())
    
    # Save unique ports to a new CSV
    pd.DataFrame({"UniquePorts": unique_ports}).to_csv(output_csv, index=False)
    print(f"Unique ports saved to {output_csv}")

# Example usage
input_csv = "test.csv"
output_csv = "unique_ports.csv"
extract_unique_ports(input_csv, output_csv)
