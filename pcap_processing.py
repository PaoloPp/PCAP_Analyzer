"""Convenience wrappers around :mod:`pcap_analyzer.pcap_ops`."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import constants as c
from pcap_analyzer.pcap_ops import extract_dns_packets, slice_pcap_by_timestamp, split_pcap_by_ips


def extract_pcap(
    file_name: str,
    ip_addresses: Iterable[str],
    *,
    output_dir: str | Path | None = None,
    append: bool = False,
    progress_interval: int = 10_000,
):
    """Split ``file_name`` into per-IP PCAPs inside ``output_dir``."""
    base_dir = Path(output_dir) if output_dir else c.CONFIG.pcap_dir
    split_pcap_by_ips(
        c.CONFIG.resolve_pcap(file_name),
        ip_addresses,
        base_dir,
        append=append,
        progress_interval=progress_interval,
    )


def extract_pcap_timestamp(input_pcap: str, output_pcap: str, stop_timestamp: float):
    """Write packets from ``input_pcap`` to ``output_pcap`` until ``stop_timestamp``."""
    slice_pcap_by_timestamp(
        c.CONFIG.resolve_pcap(input_pcap),
        c.CONFIG.resolve_pcap(output_pcap),
        stop_timestamp,
    )


def extract_dns_pckt(pcap_inputs: Iterable[str | Path], output_pcap: str | Path):
    """Extract DNS packets from ``pcap_inputs`` into ``output_pcap``."""
    extract_dns_packets(pcap_inputs, c.CONFIG.resolve_pcap(output_pcap))


__all__ = [
    "extract_pcap",
    "extract_pcap_timestamp",
    "extract_dns_pckt",
]
