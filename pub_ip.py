"""Wrappers around :mod:`pcap_analyzer.csv_tools` for destination IP extraction."""
from __future__ import annotations

from typing import Iterable, Optional

from pcap_analyzer.csv_tools import destination_ips_for_sources


def extract_destination_ips(
    input_csv: str,
    source_ip_list: Iterable[str],
    output_csv: Optional[str] = None,
) -> list[str]:
    """Return unique destination IPs contacted by ``source_ip_list``."""
    return destination_ips_for_sources(
        input_csv,
        source_ip_list,
        output_csv=output_csv,
    )


__all__ = ["extract_destination_ips"]
