"""Utilities for working with packet metadata stored as CSV."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

import pandas as pd


@dataclass(slots=True)
class FilterStats:
    """Result returned by :func:`filter_csv_by_ips`."""

    rows_scanned: int
    rows_matched: int
    distinct_ips_matched: int


def filter_csv_by_ips(
    csv_path: str | Path,
    ip_items: Iterable[str],
    *,
    output_csv: str | Path | None = None,
    per_ip_dir: str | Path | None = None,
    src_col: str = "SourceIP",
    dst_col: str = "DestinationIP",
    chunksize: int = 200_000,
    output_columns: Optional[Sequence[str]] = None,
) -> FilterStats:
    """Filter ``csv_path`` to rows where either IP matches ``ip_items``."""
    exact_ips, subnets = _parse_ip_items(ip_items)

    if per_ip_dir:
        Path(per_ip_dir).mkdir(parents=True, exist_ok=True)

    rows_scanned = 0
    rows_matched = 0
    ips_seen: set[str] = set()

    combined_header_written = False

    for chunk in pd.read_csv(csv_path, chunksize=chunksize):
        rows_scanned += len(chunk)
        if src_col not in chunk.columns or dst_col not in chunk.columns:
            raise ValueError(f"Missing required columns: {src_col!r} or {dst_col!r}")

        mask = pd.Series(False, index=chunk.index)
        if exact_ips:
            mask |= chunk[src_col].isin(exact_ips) | chunk[dst_col].isin(exact_ips)

        if subnets:
            pending = chunk.loc[~mask, [src_col, dst_col]]
            if not pending.empty:
                subnet_mask_src = pending[src_col].apply(_ip_in_any_subnet, args=(subnets,))
                subnet_mask_dst = pending[dst_col].apply(_ip_in_any_subnet, args=(subnets,))
                mask |= pd.Series(False, index=chunk.index)
                mask.loc[pending.index] = subnet_mask_src | subnet_mask_dst

        filtered = chunk.loc[mask].copy()
        if filtered.empty:
            continue

        rows_matched += len(filtered)
        ips_seen.update(filtered[src_col].astype(str))
        ips_seen.update(filtered[dst_col].astype(str))

        if output_columns:
            existing_columns = [col for col in output_columns if col in filtered.columns]
            filtered = filtered[existing_columns]

        if output_csv:
            filtered.to_csv(
                output_csv,
                mode="a",
                index=False,
                header=not combined_header_written,
            )
            combined_header_written = True

        if per_ip_dir and exact_ips:
            for ip in exact_ips:
                ip_mask = (filtered[src_col] == ip) | (filtered[dst_col] == ip)
                if not ip_mask.any():
                    continue
                out_path = Path(per_ip_dir) / f"{ip}.csv"
                filtered.loc[ip_mask].to_csv(
                    out_path,
                    mode="a",
                    index=False,
                    header=not out_path.exists(),
                )

    return FilterStats(
        rows_scanned=rows_scanned,
        rows_matched=rows_matched,
        distinct_ips_matched=len(ips_seen),
    )


def unique_destination_ports(
    csv_path: str | Path,
    *,
    output_csv: str | Path | None = None,
    ip_filter: Optional[Iterable[str]] = None,
    source_column: str = "SourceIP",
    port_column: str = "DestinationPort",
) -> list[int]:
    """Return sorted unique destination ports from ``csv_path``."""
    df = pd.read_csv(csv_path, usecols=lambda col: col in {source_column, port_column})
    if ip_filter:
        ip_list = {str(ip) for ip in ip_filter}
        df = df[df[source_column].isin(ip_list)]
    ports = sorted(df[port_column].dropna().astype(int).unique())

    if output_csv:
        pd.DataFrame({port_column: ports}).to_csv(output_csv, index=False)

    return ports


def destination_ips_for_sources(
    csv_path: str | Path,
    source_ips: Iterable[str],
    *,
    output_csv: str | Path | None = None,
    source_column: str = "SourceIP",
    destination_column: str = "DestinationIP",
) -> list[str]:
    """Return unique destination IPs contacted by ``source_ips``."""
    ip_list = {str(ip) for ip in source_ips}
    df = pd.read_csv(
        csv_path,
        usecols=lambda col: col in {source_column, destination_column},
    )
    df = df[df[source_column].isin(ip_list)]
    unique_destinations = sorted(df[destination_column].dropna().astype(str).unique())

    if output_csv:
        pd.DataFrame({destination_column: unique_destinations}).to_csv(
            output_csv,
            index=False,
        )

    return unique_destinations


def _parse_ip_items(items: Iterable[str]) -> tuple[set[str], list[ipaddress._BaseNetwork]]:
    exact_ips: set[str] = set()
    subnets: list[ipaddress._BaseNetwork] = []
    for item in items:
        item = str(item).strip()
        if not item:
            continue
        if "/" in item:
            subnets.append(ipaddress.ip_network(item, strict=False))
        else:
            exact_ips.add(item)
    return exact_ips, subnets


def _ip_in_any_subnet(ip: str, subnets: Sequence[ipaddress._BaseNetwork]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(ip_obj in subnet for subnet in subnets)


__all__ = [
    "FilterStats",
    "filter_csv_by_ips",
    "unique_destination_ports",
    "destination_ips_for_sources",
]
