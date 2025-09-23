"""Wrappers around :mod:`pcap_analyzer.csv_tools`."""
from __future__ import annotations

from typing import Iterable, Optional, Sequence

from pcap_analyzer.csv_tools import FilterStats, filter_csv_by_ips


def extract_traffic_by_ips(
    csv_path: str,
    ip_items: Iterable[str],
    *,
    output_csv: Optional[str] = None,
    per_ip_dir: Optional[str] = None,
    src_col: str = "SourceIP",
    dst_col: str = "DestinationIP",
    chunksize: int = 200_000,
    output_columns: Optional[Sequence[str]] = None,
) -> FilterStats:
    """Filter ``csv_path`` for rows that match any IP or subnet in ``ip_items``."""
    return filter_csv_by_ips(
        csv_path,
        ip_items,
        output_csv=output_csv,
        per_ip_dir=per_ip_dir,
        src_col=src_col,
        dst_col=dst_col,
        chunksize=chunksize,
        output_columns=output_columns,
    )


__all__ = ["extract_traffic_by_ips", "FilterStats"]
