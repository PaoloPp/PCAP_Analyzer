"""Command line interface for the PCAP analyzer."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List

from .anonymize import IPAnonymizer, IPGroupMapping
from .config import DEFAULT_PROTOCOL_MAPPING
from .csv_tools import (
    destination_ips_for_sources,
    filter_csv_by_ips,
    unique_destination_ports,
)
from .metadata import MetadataWriter
from .packets import PacketFormatter
from .pcap_ops import slice_pcap_by_timestamp, split_pcap_by_ips
from .reporting import build_association_table, generate_summary_table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Utilities for analysing PCAP metadata")
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_metadata_parser(subparsers)
    _add_filter_parser(subparsers)
    _add_split_parser(subparsers)
    _add_slice_parser(subparsers)
    _add_anonymize_csv_parser(subparsers)
    _add_unique_ports_parser(subparsers)
    _add_destination_ips_parser(subparsers)
    _add_association_parser(subparsers)
    _add_summary_parser(subparsers)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


# ---------------------------------------------------------------------------
# parser builders


def _add_metadata_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("metadata", help="Export CSV data from a PCAP file")
    parser.add_argument("pcap", help="Path to the input PCAP file")
    parser.add_argument("metadata", help="Path to the metadata CSV to write")
    parser.add_argument("--payload", help="Optional payload CSV output")
    parser.add_argument("--data", help="Optional raw data CSV output")
    parser.add_argument(
        "--stop",
        type=float,
        help="Stop processing once this epoch timestamp is exceeded",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1000,
        help="Number of packets to buffer before writing to disk",
    )
    parser.set_defaults(func=_cmd_metadata)


def _add_filter_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("filter-csv", help="Filter a CSV to specific IP addresses")
    parser.add_argument("csv", help="Input CSV file")
    parser.add_argument(
        "--ip",
        dest="ips",
        action="append",
        required=True,
        help="IP address or CIDR subnet to match (can be repeated)",
    )
    parser.add_argument("--output", help="Path to write the combined filtered CSV")
    parser.add_argument("--per-ip-dir", help="Directory where per-IP CSVs will be written")
    parser.add_argument("--src-col", default="SourceIP", help="Name of the source IP column")
    parser.add_argument("--dst-col", default="DestinationIP", help="Name of the destination IP column")
    parser.add_argument(
        "--chunksize",
        type=int,
        default=200_000,
        help="Number of rows per processing chunk",
    )
    parser.set_defaults(func=_cmd_filter_csv)


def _add_split_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("split-pcap", help="Split a PCAP into per-IP files")
    parser.add_argument("pcap", help="Input PCAP file")
    parser.add_argument("output_dir", help="Directory that will receive the per-IP PCAP files")
    parser.add_argument(
        "--ip",
        dest="ips",
        action="append",
        required=True,
        help="IP address that should receive its own PCAP (repeat for multiple)",
    )
    parser.add_argument("--append", action="store_true", help="Append to existing per-IP PCAPs")
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=10_000,
        help="Log progress after this many packets",
    )
    parser.set_defaults(func=_cmd_split_pcap)


def _add_slice_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("slice-pcap", help="Write packets until a timestamp is reached")
    parser.add_argument("pcap", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("stop", type=float, help="Epoch timestamp at which to stop writing")
    parser.add_argument("--append", action="store_true", help="Append to the destination file")
    parser.set_defaults(func=_cmd_slice_pcap)


def _add_anonymize_csv_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("anonymize-csv", help="Anonymize IP addresses in a CSV file")
    parser.add_argument("input", help="Input CSV file")
    parser.add_argument("output", help="Output CSV file")
    parser.add_argument("--tracking", help="Optional CSV file to store replacement mappings")
    parser.add_argument(
        "--group",
        action="append",
        nargs="+",
        metavar=("SUBNET", "IP"),
        help="Define a private IP group: SUBNET IP [IP ...]",
    )
    parser.add_argument(
        "--default-subnet",
        default="10.0.0.0/8",
        help="Subnet to use when no private mapping is found",
    )
    parser.add_argument("--seed", type=int, help="Seed used when generating anonymised IPs")
    parser.add_argument("--src-col", default="SourceIP")
    parser.add_argument("--dst-col", default="DestinationIP")
    parser.set_defaults(func=_cmd_anonymize_csv)


def _add_unique_ports_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("unique-ports", help="List unique destination ports")
    parser.add_argument("csv", help="Input CSV file")
    parser.add_argument("--output", help="Optional CSV file for the unique ports")
    parser.add_argument(
        "--source-ip",
        action="append",
        dest="source_ips",
        help="Filter by specific source IPs (repeatable)",
    )
    parser.set_defaults(func=_cmd_unique_ports)


def _add_destination_ips_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("destination-ips", help="List unique destination IPs contacted by a set of sources")
    parser.add_argument("csv", help="Input CSV file")
    parser.add_argument("--source-ip", action="append", dest="source_ips", required=True)
    parser.add_argument("--output", help="Optional CSV file for the destination IPs")
    parser.set_defaults(func=_cmd_destination_ips)


def _add_association_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("associations", help="Build a host/port association table")
    parser.add_argument("csv", help="Input CSV file")
    parser.add_argument("--output", help="Output CSV file")
    parser.set_defaults(func=_cmd_associations)


def _add_summary_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("summary", help="Generate a traffic summary table for a set of IPs")
    parser.add_argument("csv", help="Input CSV file")
    parser.add_argument("--ip", dest="ips", action="append", required=True)
    parser.set_defaults(func=_cmd_summary)


# ---------------------------------------------------------------------------
# command handlers


def _cmd_metadata(args: argparse.Namespace) -> int:
    formatter = PacketFormatter(DEFAULT_PROTOCOL_MAPPING)
    writer = MetadataWriter(formatter, chunk_size=args.chunk_size)
    stats = writer.export(
        args.pcap,
        metadata_csv=args.metadata,
        payload_csv=args.payload,
        data_csv=args.data,
        stop_time=args.stop,
    )
    for key, value in stats.as_dict().items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    return 0


def _cmd_filter_csv(args: argparse.Namespace) -> int:
    stats = filter_csv_by_ips(
        args.csv,
        args.ips,
        output_csv=args.output,
        per_ip_dir=args.per_ip_dir,
        src_col=args.src_col,
        dst_col=args.dst_col,
        chunksize=args.chunksize,
    )
    print(
        f"Rows scanned: {stats.rows_scanned}\n"
        f"Rows matched: {stats.rows_matched}\n"
        f"Distinct IPs matched: {stats.distinct_ips_matched}"
    )
    return 0


def _cmd_split_pcap(args: argparse.Namespace) -> int:
    counts = split_pcap_by_ips(
        args.pcap,
        args.ips,
        args.output_dir,
        append=args.append,
        progress_interval=args.progress_interval,
    )
    for ip, count in sorted(counts.items()):
        print(f"{ip}: {count} packets")
    return 0


def _cmd_slice_pcap(args: argparse.Namespace) -> int:
    written = slice_pcap_by_timestamp(
        args.pcap,
        args.output,
        args.stop,
        append=args.append,
    )
    print(f"Wrote {written} packets to {args.output}")
    return 0


def _cmd_anonymize_csv(args: argparse.Namespace) -> int:
    groups: List[IPGroupMapping] = []
    if args.group:
        for group in args.group:
            if len(group) < 2:
                raise SystemExit("Each --group must specify a subnet followed by one or more IPs")
            subnet, *ips = group
            groups.append(IPGroupMapping(private_ips=ips, subnet=subnet))

    anonymizer = IPAnonymizer(groups, default_subnet=args.default_subnet, seed=args.seed)
    anonymizer.anonymize_csv(
        args.input,
        args.output,
        tracking_file=args.tracking,
        src_col=args.src_col,
        dst_col=args.dst_col,
    )
    print(f"Anonymised CSV written to {args.output}")
    if args.tracking:
        print(f"Tracking table written to {args.tracking}")
    return 0


def _cmd_unique_ports(args: argparse.Namespace) -> int:
    ports = unique_destination_ports(
        args.csv,
        output_csv=args.output,
        ip_filter=args.source_ips,
    )
    print("Unique destination ports:")
    for port in ports:
        print(port)
    return 0


def _cmd_destination_ips(args: argparse.Namespace) -> int:
    ips = destination_ips_for_sources(
        args.csv,
        args.source_ips,
        output_csv=args.output,
    )
    print("Destination IPs:")
    for ip in ips:
        print(ip)
    return 0


def _cmd_associations(args: argparse.Namespace) -> int:
    table = build_association_table(args.csv, output_csv=args.output)
    print(table.head().to_string(index=False))
    if args.output:
        print(f"Association table written to {args.output}")
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    table = generate_summary_table(args.csv, args.ips)
    if table.empty:
        print("No matching traffic found")
    else:
        print(table.to_string(index=False))
    return 0


__all__ = ["build_parser", "main"]
