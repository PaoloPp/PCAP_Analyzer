"""Utility wrappers for extracting destination ports."""
from __future__ import annotations

from typing import Iterable, Optional

from pcap_analyzer.csv_tools import unique_destination_ports


def extract_unique_ports(input_csv: str, output_csv: Optional[str] = None) -> list[int]:
    """Return sorted unique destination ports from ``input_csv``."""
    return unique_destination_ports(input_csv, output_csv=output_csv)


def extract_unique_ports_with_ip_filter(
    input_csv: str,
    output_csv: Optional[str],
    ip_list: Iterable[str],
) -> list[int]:
    """Return unique destination ports where the source IP is within ``ip_list``."""
    return unique_destination_ports(
        input_csv,
        output_csv=output_csv,
        ip_filter=ip_list,
    )


__all__ = [
    "extract_unique_ports",
    "extract_unique_ports_with_ip_filter",
]
