"""Legacy helpers built on top of :mod:`pcap_analyzer.packets`."""
from __future__ import annotations

from typing import Dict

from pcap_analyzer.config import DEFAULT_PROTOCOL_MAPPING
from pcap_analyzer.packets import PacketFormatter

_formatter = PacketFormatter(DEFAULT_PROTOCOL_MAPPING)


def process_pckt(packet, number: int) -> Dict:
    """Return metadata for ``packet`` if available."""
    return _formatter.collect(packet, number).metadata or {}


def process_data_pckt(packet, number: int) -> Dict:
    """Return payload data for ``packet`` if available."""
    return _formatter.collect(packet, number).data or {}


def process_metadata_payload(packet, number: int):
    """Return metadata and payload dictionaries for ``packet``."""
    record = _formatter.collect(packet, number)
    return record.metadata or {}, record.payload or {}


def get_protocol_name(protocol_number: int | None) -> str:
    """Return the human readable name for ``protocol_number``."""
    return _formatter.protocol_name(protocol_number)


__all__ = [
    "process_pckt",
    "process_data_pckt",
    "process_metadata_payload",
    "get_protocol_name",
]
