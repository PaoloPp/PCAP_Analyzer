"""IP anonymisation helpers and backwards compatible wrappers."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import pandas as pd

from pcap_analyzer.anonymize import IPAnonymizer, IPGroupMapping


def csv_substitute_ip_pairs(
    input_csv: str,
    output_csv: str,
    ip_list: Sequence[str],
    substitute_ip: str,
) -> None:
    """Replace destination/source IPs when the counterpart matches ``ip_list``."""
    df = pd.read_csv(input_csv)
    df.loc[df["SourceIP"].isin(ip_list), "DestinationIP"] = substitute_ip
    df.loc[df["DestinationIP"].isin(ip_list), "SourceIP"] = substitute_ip
    df.to_csv(output_csv, index=False)


def csv_substitute_ips_for_sublists(
    input_csv: str,
    output_csv: str,
    ip_sublists_with_subs: Sequence[tuple[Sequence[str], str]],
) -> None:
    """Apply a static substitution for each IP in ``ip_sublists_with_subs``."""
    df = pd.read_csv(input_csv)
    for ip_sublist, substitute_ip in ip_sublists_with_subs:
        df.loc[df["SourceIP"].isin(ip_sublist), "DestinationIP"] = substitute_ip
        df.loc[df["DestinationIP"].isin(ip_sublist), "SourceIP"] = substitute_ip
    df.to_csv(output_csv, index=False)


def csv_substitute_ips_for_sublists_chunked(
    input_csv: str,
    output_csv: str,
    ip_sublists_with_subs: Sequence[tuple[Sequence[str], str]],
    *,
    chunksize: int = 10_000,
) -> None:
    """Chunked variant of :func:`csv_substitute_ips_for_sublists`."""
    with pd.read_csv(input_csv, chunksize=chunksize) as reader:
        with open(output_csv, "w", newline="") as fh:
            writer = None
            for chunk in reader:
                for ip_sublist, substitute_ip in ip_sublists_with_subs:
                    mask_src = chunk["SourceIP"].isin(ip_sublist)
                    chunk.loc[mask_src, "DestinationIP"] = substitute_ip
                    mask_dst = chunk["DestinationIP"].isin(ip_sublist)
                    chunk.loc[mask_dst, "SourceIP"] = substitute_ip
                if writer is None:
                    chunk.to_csv(fh, index=False)
                    writer = True
                else:
                    chunk.to_csv(fh, index=False, header=False)


def anonymize_ip_by_subnet(
    input_pcap: str,
    output_pcap: str,
    tracking_file: str,
    ip_groups: Mapping[Sequence[str], str] | Iterable[IPGroupMapping],
    *,
    default_subnet: str = "10.0.0.0/8",
    seed: int | None = None,
) -> int:
    """Anonymise ``input_pcap`` writing the result to ``output_pcap``."""
    anonymizer = IPAnonymizer(ip_groups, default_subnet=default_subnet, seed=seed)
    return anonymizer.anonymize_pcap(
        input_pcap,
        output_pcap,
        tracking_file=tracking_file,
    )


def anonymize_ip_by_subnet_csv(
    input_csv: str,
    output_csv: str,
    *,
    tracking_file: str | Path | None = "ip_replacements.csv",
    ip_groups: Mapping[Sequence[str], str] | Iterable[IPGroupMapping] = (),
    src_col: str = "SourceIP",
    dst_col: str = "DestinationIP",
    default_subnet: str = "10.0.0.0/8",
    seed: int | None = None,
) -> None:
    """Anonymise public IPs in ``input_csv`` writing the result to ``output_csv``."""
    anonymizer = IPAnonymizer(ip_groups, default_subnet=default_subnet, seed=seed)
    anonymizer.anonymize_csv(
        input_csv,
        output_csv,
        tracking_file=tracking_file,
        src_col=src_col,
        dst_col=dst_col,
    )


def load_ip_groups_from_csv(path: str | Path) -> list[IPGroupMapping]:
    """Utility helper to load IP groups from a CSV containing subnet definitions."""
    groups: list[IPGroupMapping] = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            subnet = row.get("Subnet")
            ips = [value for key, value in row.items() if key != "Subnet" and value]
            if subnet and ips:
                groups.append(IPGroupMapping(private_ips=ips, subnet=subnet))
    return groups


__all__ = [
    "csv_substitute_ip_pairs",
    "csv_substitute_ips_for_sublists",
    "csv_substitute_ips_for_sublists_chunked",
    "anonymize_ip_by_subnet",
    "anonymize_ip_by_subnet_csv",
    "load_ip_groups_from_csv",
]
