"""Helpers for building host/port association tables."""
from __future__ import annotations

from typing import Optional

import pandas as pd

from pcap_analyzer.reporting import build_association_table


def create_association_csv(input_csv: str, output_csv: Optional[str] = None) -> pd.DataFrame:
    """Return a DataFrame of host/port associations and optionally write it."""
    return build_association_table(input_csv, output_csv=output_csv)


__all__ = ["create_association_csv"]
