"""CSV generation helpers built on :mod:`pcap_analyzer.metadata`."""
from __future__ import annotations

from pcap_analyzer.metadata import MetadataWriter
from pcap_analyzer.packets import PacketFormatter
from pcap_analyzer.config import DEFAULT_PROTOCOL_MAPPING

_formatter = PacketFormatter(DEFAULT_PROTOCOL_MAPPING)


def create_metadata_csv(pcap_path: str, output_csv: str, stop_timestamp: float | None = None, *, chunk_size: int = 1000):
    """Write packet metadata from ``pcap_path`` to ``output_csv``."""
    writer = MetadataWriter(_formatter, chunk_size=chunk_size)
    return writer.export(pcap_path, metadata_csv=output_csv, stop_time=stop_timestamp)


def create_data_csv(pcap_path: str, output_csv: str, stop_timestamp: float | None = None, *, chunk_size: int = 1000):
    """Write base64 encoded payload data from ``pcap_path`` to ``output_csv``."""
    writer = MetadataWriter(_formatter, chunk_size=chunk_size)
    return writer.export(pcap_path, data_csv=output_csv, stop_time=stop_timestamp)


def create_data_payload_csv(
    pcap_path: str,
    metadata_csv: str,
    payload_csv: str,
    stop_timestamp: float | None = None,
    *,
    chunk_size: int = 1000,
):
    """Write both metadata and payload CSVs from ``pcap_path``."""
    writer = MetadataWriter(_formatter, chunk_size=chunk_size)
    return writer.export(
        pcap_path,
        metadata_csv=metadata_csv,
        payload_csv=payload_csv,
        stop_time=stop_timestamp,
    )


__all__ = [
    "create_metadata_csv",
    "create_data_csv",
    "create_data_payload_csv",
]
