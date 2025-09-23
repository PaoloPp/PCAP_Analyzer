"""Configuration helpers for the PCAP analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable

DEFAULT_PROTOCOL_MAPPING: Dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    27: "RDP",
    132: "SCTP",
}


@dataclass(slots=True)
class AnalyzerConfig:
    """Paths and lookup tables used throughout the toolkit."""

    pcap_dir: Path = Path("PCAP")
    csv_dir: Path = Path("csv")
    plot_dir: Path = Path("plots")
    ip_prefix: str = "192.168.0."
    protocol_mapping: Dict[int, str] = field(
        default_factory=lambda: DEFAULT_PROTOCOL_MAPPING.copy()
    )

    def ensure_directories(self) -> None:
        """Ensure that the common output directories exist."""
        for path in (self.pcap_dir, self.csv_dir, self.plot_dir):
            path.mkdir(parents=True, exist_ok=True)

    def resolve_pcap(self, path: str | Path) -> Path:
        """Return an absolute path for a PCAP file relative to ``pcap_dir``."""
        return self._resolve(self.pcap_dir, path)

    def resolve_csv(self, path: str | Path) -> Path:
        """Return an absolute path for a CSV file relative to ``csv_dir``."""
        return self._resolve(self.csv_dir, path)

    @staticmethod
    def _resolve(base: Path, path: str | Path) -> Path:
        candidate = Path(path)
        if candidate.is_absolute():
            return candidate
        return base / candidate

    def format_ip(self, suffix: int) -> str:
        """Convenience helper used by some legacy scripts."""
        return f"{self.ip_prefix}{suffix}"

    def update_protocols(self, entries: Iterable[tuple[int, str]]) -> None:
        """Update the protocol lookup table with additional entries."""
        self.protocol_mapping.update(dict(entries))


__all__ = ["AnalyzerConfig", "DEFAULT_PROTOCOL_MAPPING"]
