"""I/O helpers around Scapy's PCAP readers."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from scapy.packet import Packet
from scapy.utils import PcapReader, PcapWriter

logger = logging.getLogger(__name__)


@contextmanager
def pcap_reader(path: str | Path) -> Iterator[PcapReader]:
    """Yield a :class:`~scapy.utils.PcapReader` for ``path``."""
    path = Path(path)
    logger.info("Opening PCAP file %s", path)
    reader = PcapReader(str(path))
    try:
        yield reader
    finally:
        reader.close()
        logger.info("Closed PCAP file %s", path)


def iter_packets(path: str | Path, *, limit: int | None = None) -> Iterator[Packet]:
    """Iterate packets from ``path`` with an optional limit."""
    with pcap_reader(path) as reader:
        for index, packet in enumerate(reader, start=1):
            yield packet
            if limit is not None and index >= limit:
                break


def write_packets(
    path: str | Path,
    packets: Iterable[Packet],
    *,
    append: bool = False,
    sync: bool = True,
) -> int:
    """Write ``packets`` to ``path`` returning the number of packets written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    writer = PcapWriter(str(path), append=append, sync=sync)
    written = 0
    try:
        for packet in packets:
            writer.write(packet)
            written += 1
    finally:
        writer.close()
        logger.info("Wrote %s packets to %s", written, path)

    return written


__all__ = ["pcap_reader", "iter_packets", "write_packets"]
