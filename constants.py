"""Backward compatible constants that proxy :mod:`pcap_analyzer.config`."""
from __future__ import annotations

from pcap_analyzer.config import AnalyzerConfig, DEFAULT_PROTOCOL_MAPPING

CONFIG = AnalyzerConfig()
CONFIG.ensure_directories()

PCAP_DIR = f"{CONFIG.pcap_dir}/"
CSV_DIR = f"{CONFIG.csv_dir}/"
PLOT_DIR = f"{CONFIG.plot_dir}/"
IP_PREFIX = CONFIG.ip_prefix
protocol_mapping = CONFIG.protocol_mapping

__all__ = [
    "CONFIG",
    "PCAP_DIR",
    "CSV_DIR",
    "PLOT_DIR",
    "IP_PREFIX",
    "protocol_mapping",
    "DEFAULT_PROTOCOL_MAPPING",
]
