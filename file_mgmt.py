"""Compatibility wrappers around :mod:`pcap_analyzer.io`."""
from __future__ import annotations

import logging
from pathlib import Path

from scapy.utils import PcapReader

logger = logging.getLogger(__name__)


def open_pcap(name: str | Path) -> PcapReader:
    """Return a :class:`~scapy.utils.PcapReader` for ``name``."""
    path = Path(name)
    logger.info("Opening PCAP file %s", path)
    return PcapReader(str(path))


__all__ = ["open_pcap"]
