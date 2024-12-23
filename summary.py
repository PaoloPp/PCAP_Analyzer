import pandas as pd
import games as g

def generate_summary_table(csv_file, ip_list):
    """
    Generates a summary table similar to the given format from the CSV file,
    filtering on a specified list of IPs.

    Parameters:
        csv_file (str): Path to the CSV file.
        ip_list (list): List of IPs to filter the data.

    Returns:
        summary_table (pd.DataFrame): A summary table as a DataFrame.
    """
    # Load the CSV file
    df = pd.read_csv(csv_file)

    # Ensure necessary columns exist
    required_columns = ["Time", "SourceIP", "DestinationIP", "Length"]
    if not set(required_columns).issubset(df.columns):
        raise ValueError("CSV file must include the following columns: Time, SourceIP, DestinationIP, Length")

    # Filter rows where SourceIP or DestinationIP is in the ip_list
    df = df[(df['SourceIP'].isin(ip_list)) | (df['DestinationIP'].isin(ip_list))]

    # Total messages in each direction
    client_to_server = df[df['DestinationIP'].isin(ip_list)].shape[0]
    server_to_client = df[df['SourceIP'].isin(ip_list)].shape[0]

    # Total sessions (unique client-server pairs)
    #unique_sessions = df.groupby(['SourceIP', 'DestinationIP']).ngroups

    # Alternative method to calculate unique sessions (both directions are counted as a single association)
    df['SessionKey'] = df.apply(lambda row: tuple(sorted([row['SourceIP'], row['DestinationIP']])), axis=1)
    unique_sessions = df['SessionKey'].nunique()


    # Session durations (if time is in epoch seconds)
    df['Time'] = pd.to_datetime(df['Time'], unit='s')
    session_durations = df.groupby(['SourceIP', 'DestinationIP'])['Time'].agg([min, max])
    session_durations['Duration'] = (session_durations['max'] - session_durations['min']).dt.total_seconds()

    avg_session_duration = session_durations['Duration'].mean()
    median_session_duration = session_durations['Duration'].median()
    std_session_duration = session_durations['Duration'].std()

    # Messages per session
    msgs_per_session = df.groupby(['SourceIP', 'DestinationIP']).size()
    avg_msgs = msgs_per_session.mean()
    median_msgs = msgs_per_session.median()
    std_msgs = msgs_per_session.std()

    # Bit rates in KBps (Length column)
    total_length = df['Length'].sum() / 1024  # Convert to KB
    total_duration = (df['Time'].max() - df['Time'].min()).total_seconds()
    avg_bitrate = total_length / total_duration if total_duration > 0 else 0

    # Log size (approximate size of all packets in bytes)
    log_size = df['Length'].sum() / (1024 * 1024)  # Convert to MB

    # Create a summary dictionary
    summary_data = {
        "Time span": f"{total_duration/3600:.1f} h",
        "Client-to-server messages": client_to_server,
        "Server-to-client messages": server_to_client,
        "Observed sessions": unique_sessions,
        "Session duration(s) (avg/med/stdev)": f"{avg_session_duration:.1f}/{median_session_duration:.1f}/{std_session_duration:.1f}",
        "Msgs per session (avg/med/stdev)": f"{avg_msgs:.1f}/{median_msgs:.1f}/{std_msgs:.1f}",
        "Bit rates (KBps) (avg)": f"{avg_bitrate:.1f}",
        "Total volume of traffic": f"{log_size:.2f} MB",
    }

    # Convert summary to DataFrame for a table-like format
    summary_table = pd.DataFrame(summary_data.items(), columns=['Metric', 'Value'])
    return summary_table

#summary_table = generate_summary_table("csv/28_06_1000-1330_metadata.csv", g.CLASH_ROYALE)
#print(summary_table)
#summary_table = generate_summary_table("csv/28_06_1000-1330_metadata.csv", g.ROCKET_LEAGUE)
#print(summary_table)
#summary_table = generate_summary_table("csv/28_06_1000-1330_metadata.csv", g.EAFC)
#print(summary_table)
#summary_table = generate_summary_table("csv/28_06_1000-1330_metadata.csv", g.CHESS)
#print(summary_table)
#summary_table = generate_summary_table("csv/28_06_1000-1330_metadata.csv", g.BRAWLHALLA)
#print(summary_table)
#summary_table = generate_summary_table("csv/28_06_1000-1330_metadata.csv", g.MGMT)
#print(summary_table)