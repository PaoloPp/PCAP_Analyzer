"""Higher level operations for working with PCAP files."""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator

from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.utils import PcapWriter

from .io import pcap_reader

logger = logging.getLogger(__name__)


def slice_pcap_by_timestamp(
    input_pcap: str | Path,
    output_pcap: str | Path,
    stop_timestamp: float,
    *,
    append: bool = False,
    sync: bool = True,
) -> int:
    """Write packets from ``input_pcap`` to ``output_pcap`` until ``stop_timestamp``."""
    output_path = Path(output_pcap)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    writer = PcapWriter(str(output_path), append=append, sync=sync)
    written = 0
    try:
        with pcap_reader(input_pcap) as reader:
            for packet in reader:
                if float(packet.time) > stop_timestamp:
                    break
                writer.write(packet)
                written += 1
    finally:
        writer.close()
        logger.info("Wrote %s packets to %s", written, output_path)

    return written


def split_pcap_by_ips(
    pcap_path: str | Path,
    ip_addresses: Iterable[str],
    output_dir: str | Path,
    *,
    append: bool = False,
    progress_interval: int = 10_000,
) -> Dict[str, int]:
    """Split ``pcap_path`` into per-IP PCAP files in ``output_dir``."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ip_set = {str(ip).strip() for ip in ip_addresses if str(ip).strip()}

    if not ip_set:
        raise ValueError("No IP addresses supplied")

    writers: Dict[str, PcapWriter] = {}
    counts: Dict[str, int] = defaultdict(int)

    try:
        with pcap_reader(pcap_path) as reader:
            for index, packet in enumerate(reader, start=1):
                ip_layer = packet.getlayer(IP)
                if ip_layer is None:
                    continue

                matches = []
                if ip_layer.src in ip_set:
                    matches.append(ip_layer.src)
                if ip_layer.dst in ip_set:
                    matches.append(ip_layer.dst)

                if not matches:
                    continue

                for ip in matches:
                    writer = writers.get(ip)
                    if writer is None:
                        ip_dir = output_dir / ip
                        ip_dir.mkdir(parents=True, exist_ok=True)
                        out_path = ip_dir / f"{ip}_{Path(pcap_path).name}"
                        writer = PcapWriter(str(out_path), append=append, sync=True)
                        writers[ip] = writer
                    writer.write(packet)
                    counts[ip] += 1

                if progress_interval and index % progress_interval == 0:
                    logger.info("Processed %s packets", index)
    finally:
        for writer in writers.values():
            writer.close()

    return dict(counts)


def extract_dns_packets(
    pcap_inputs: Iterable[str | Path],
    output_pcap: str | Path,
    *,
    append: bool = False,
    sync: bool = True,
) -> int:
    """Extract DNS packets from ``pcap_inputs`` into ``output_pcap``."""
    output_path = Path(output_pcap)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    writer = PcapWriter(str(output_path), append=append, sync=sync)
    written = 0
    try:
        for path in _expand_inputs(pcap_inputs):
            with pcap_reader(path) as reader:
                for packet in reader:
                    if packet.haslayer(DNS):
                        writer.write(packet)
                        written += 1
    finally:
        writer.close()
        logger.info("Wrote %s DNS packets to %s", written, output_path)

    return written


def _expand_inputs(paths: Iterable[str | Path]) -> Iterator[Path]:
    for path in paths:
        candidate = Path(path)
        if candidate.is_dir():
            yield from sorted(candidate.glob("**/*.pcap"))
        else:
            yield candidate


__all__ = [
    "slice_pcap_by_timestamp",
    "split_pcap_by_ips",
    "extract_dns_packets",
]
