"""Reporting helpers for the PCAP analyzer."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pandas as pd


def build_association_table(
    csv_path: str | Path,
    *,
    output_csv: str | Path | None = None,
    source_column: str = "SourceIP",
    destination_column: str = "DestinationIP",
    source_port_column: str = "SourcePort",
    destination_port_column: str = "DestinationPort",
) -> pd.DataFrame:
    """Return a table counting packet associations between hosts and ports."""
    df = pd.read_csv(csv_path)
    associations = (
        df.groupby(
            [
                source_column,
                destination_column,
                source_port_column,
                destination_port_column,
            ]
        )
        .size()
        .reset_index(name="PacketCount")
        .sort_values("PacketCount", ascending=False)
    )

    if output_csv:
        associations.to_csv(output_csv, index=False)

    return associations


def generate_summary_table(
    csv_path: str | Path,
    ip_list: Iterable[str],
    *,
    source_column: str = "SourceIP",
    destination_column: str = "DestinationIP",
    time_column: str = "Time",
    length_column: str = "Length",
) -> pd.DataFrame:
    """Return a summary table describing the traffic involving ``ip_list``."""
    df = pd.read_csv(csv_path)
    ips = set(str(ip) for ip in ip_list)
    df = df[
        df[source_column].isin(ips) | df[destination_column].isin(ips)
    ].copy()
    if df.empty:
        return pd.DataFrame(columns=["Metric", "Value"])

    df["SessionKey"] = df.apply(
        lambda row: tuple(sorted([row[source_column], row[destination_column]])), axis=1
    )
    df[time_column] = pd.to_datetime(df[time_column], unit="s", errors="coerce")
    df = df.dropna(subset=[time_column])

    client_to_server = df[df[destination_column].isin(ips)].shape[0]
    server_to_client = df[df[source_column].isin(ips)].shape[0]
    observed_sessions = df["SessionKey"].nunique()

    session_durations = df.groupby([source_column, destination_column])[time_column].agg([
        "min",
        "max",
    ])
    session_durations["Duration"] = (
        session_durations["max"] - session_durations["min"]
    ).dt.total_seconds()

    avg_duration = session_durations["Duration"].mean()
    median_duration = session_durations["Duration"].median()
    std_duration = session_durations["Duration"].std()

    messages_per_session = df.groupby([source_column, destination_column]).size()
    avg_msgs = messages_per_session.mean()
    median_msgs = messages_per_session.median()
    std_msgs = messages_per_session.std()

    total_length_kb = df[length_column].sum() / 1024
    total_duration_seconds = (
        df[time_column].max() - df[time_column].min()
    ).total_seconds()
    avg_bitrate = (
        total_length_kb / total_duration_seconds if total_duration_seconds > 0 else 0
    )
    log_size_mb = df[length_column].sum() / (1024 * 1024)

    summary_data = {
        "Time span": f"{total_duration_seconds/3600:.1f} h" if total_duration_seconds else "0 h",
        "Client-to-server messages": int(client_to_server),
        "Server-to-client messages": int(server_to_client),
        "Observed sessions": int(observed_sessions),
        "Session duration(s) (avg/med/stdev)": f"{avg_duration:.1f}/{median_duration:.1f}/{std_duration:.1f}",
        "Msgs per session (avg/med/stdev)": f"{avg_msgs:.1f}/{median_msgs:.1f}/{std_msgs:.1f}",
        "Bit rates (KBps) (avg)": f"{avg_bitrate:.1f}",
        "Total volume of traffic": f"{log_size_mb:.2f} MB",
    }

    summary_table = pd.DataFrame(summary_data.items(), columns=["Metric", "Value"])

    if summary_table.empty:
        return summary_table

    return summary_table


__all__ = ["build_association_table", "generate_summary_table"]
