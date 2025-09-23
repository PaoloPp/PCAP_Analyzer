"""CSV export helpers built on top of :mod:`pcap_analyzer.packets`."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import pandas as pd

from .io import pcap_reader
from .packets import PacketFormatter, PacketRecord


@dataclass(slots=True)
class PacketExportStats:
    """Basic metrics returned by :class:`MetadataWriter`."""

    packets_read: int = 0
    metadata_rows: int = 0
    payload_rows: int = 0
    data_rows: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "packets_read": self.packets_read,
            "metadata_rows": self.metadata_rows,
            "payload_rows": self.payload_rows,
            "data_rows": self.data_rows,
        }


class _CsvBuffer:
    """Buffered CSV writer that flushes using pandas."""

    def __init__(self, path: str | Path, chunk_size: int, columns: Iterable[str]):
        self.path = Path(path)
        self.chunk_size = chunk_size
        self.columns = list(columns)
        self._rows: list[dict] = []
        self._header_written = False
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, row: Optional[dict]) -> None:
        if not row:
            return
        self._rows.append(row)
        if len(self._rows) >= self.chunk_size:
            self.flush()

    def flush(self) -> None:
        if not self._rows:
            return
        df = pd.DataFrame(self._rows)
        mode = "a" if self._header_written else "w"
        df.to_csv(
            self.path,
            mode=mode,
            index=False,
            header=not self._header_written,
            columns=self.columns if self.columns else None,
        )
        self._header_written = True
        self._rows.clear()

    def close(self) -> None:
        self.flush()


class MetadataWriter:
    """Stream packets from PCAP files to one or more CSV outputs."""

    def __init__(self, formatter: PacketFormatter, *, chunk_size: int = 1000):
        self.formatter = formatter
        self.chunk_size = chunk_size

    def export(
        self,
        pcap_path: str | Path,
        *,
        metadata_csv: str | Path | None = None,
        payload_csv: str | Path | None = None,
        data_csv: str | Path | None = None,
        stop_time: float | None = None,
    ) -> PacketExportStats:
        """Export the requested CSVs and return summary statistics."""
        if not any((metadata_csv, payload_csv, data_csv)):
            raise ValueError("At least one output CSV must be specified")

        stats = PacketExportStats()
        metadata_buffer = (
            _CsvBuffer(metadata_csv, self.chunk_size, columns=self._metadata_columns)
            if metadata_csv
            else None
        )
        payload_buffer = (
            _CsvBuffer(payload_csv, self.chunk_size, columns=self._payload_columns)
            if payload_csv
            else None
        )
        data_buffer = (
            _CsvBuffer(data_csv, self.chunk_size, columns=self._data_columns)
            if data_csv
            else None
        )

        try:
            with pcap_reader(pcap_path) as reader:
                for index, packet in enumerate(reader, start=1):
                    if stop_time is not None and float(packet.time) > stop_time:
                        break

                    stats.packets_read += 1
                    record: PacketRecord = self.formatter.collect(packet, index)

                    if metadata_buffer:
                        metadata_buffer.append(record.metadata)
                        if record.metadata:
                            stats.metadata_rows += 1

                    if payload_buffer:
                        payload_buffer.append(record.payload)
                        if record.payload:
                            stats.payload_rows += 1

                    if data_buffer:
                        data_buffer.append(record.data)
                        if record.data:
                            stats.data_rows += 1
        finally:
            for buffer in (metadata_buffer, payload_buffer, data_buffer):
                if buffer is not None:
                    buffer.close()

        return stats

    @property
    def _metadata_columns(self) -> list[str]:
        return [
            "Time",
            "No",
            "SourceIP",
            "DestinationIP",
            "SourcePort",
            "DestinationPort",
            "SequenceNumber",
            "AcknowledgementNumber",
            "Protocol",
            "Length",
            "Load",
        ]

    @property
    def _payload_columns(self) -> list[str]:
        return ["No", "Length", "Payload"]

    @property
    def _data_columns(self) -> list[str]:
        return ["Time", "Pckt_No", "Data"]


__all__ = ["MetadataWriter", "PacketExportStats"]
