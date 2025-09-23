"""Wrappers for generating traffic summaries."""
from __future__ import annotations

from typing import Iterable

import pandas as pd

from pcap_analyzer.reporting import generate_summary_table as _generate_summary_table


def generate_summary_table(csv_file: str, ip_list: Iterable[str]) -> pd.DataFrame:
    """Return a summary table for traffic that touches ``ip_list``."""
    return _generate_summary_table(csv_file, ip_list)


__all__ = ["generate_summary_table"]
