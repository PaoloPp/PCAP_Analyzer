"""IP anonymisation helpers for CSV and PCAP data."""
from __future__ import annotations

import csv
import ipaddress
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from scapy.layers.inet import IP
from scapy.utils import PcapWriter

from .io import pcap_reader


@dataclass(slots=True)
class IPGroupMapping:
    """Describe how a group of private IPs should be anonymised."""

    private_ips: Sequence[str]
    subnet: str

    def __post_init__(self) -> None:
        if not self.private_ips:
            raise ValueError("private_ips must not be empty")
        self.private_ips = tuple(str(ip) for ip in self.private_ips)
        self.subnet = str(self.subnet)


class IPAnonymizer:
    """Anonymise public IPs while keeping private groups consistent."""

    def __init__(
        self,
        groups: Iterable[IPGroupMapping] | Mapping[Sequence[str], str],
        *,
        default_subnet: str = "10.0.0.0/8",
        seed: int | None = None,
    ):
        self.groups = tuple(_coerce_groups(groups))
        self.default_subnet = ipaddress.ip_network(default_subnet, strict=False)
        self._random = random.Random(seed)
        self._private_to_subnet = {
            ip: ipaddress.ip_network(group.subnet, strict=False)
            for group in self.groups
            for ip in group.private_ips
        }
        self.reset()

    def reset(self) -> None:
        """Clear cached mappings and tracking information."""
        self._public_to_replacement: dict[str, str] = {}
        self._tracking: set[tuple[str, str, str]] = set()

    def anonymize_pair(self, src_ip: str, dst_ip: str) -> tuple[str, str]:
        """Return anonymised ``src_ip`` and ``dst_ip`` preserving mappings."""
        new_src = self._anonymize_ip(src_ip, counterpart=dst_ip)
        new_dst = self._anonymize_ip(dst_ip, counterpart=src_ip)
        return new_src, new_dst

    def anonymize_csv(
        self,
        input_csv: str | Path,
        output_csv: str | Path,
        *,
        tracking_file: str | Path | None = None,
        src_col: str = "SourceIP",
        dst_col: str = "DestinationIP",
    ) -> None:
        """Anonymise ``input_csv`` writing the result to ``output_csv``."""
        self.reset()
        output_path = Path(output_csv)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(input_csv, newline="") as fin, open(output_path, "w", newline="") as fout:
            reader = csv.DictReader(fin)
            fieldnames = reader.fieldnames or []
            for column in (src_col, dst_col):
                if column not in fieldnames:
                    fieldnames.append(column)
            writer = csv.DictWriter(fout, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                src = str(row.get(src_col, "") or "")
                dst = str(row.get(dst_col, "") or "")
                new_src, new_dst = self.anonymize_pair(src, dst)
                row[src_col] = new_src
                row[dst_col] = new_dst
                writer.writerow(row)

        if tracking_file:
            self._write_tracking(tracking_file)

    def anonymize_pcap(
        self,
        input_pcap: str | Path,
        output_pcap: str | Path,
        *,
        tracking_file: str | Path | None = None,
        append: bool = False,
        sync: bool = True,
    ) -> int:
        """Anonymise ``input_pcap`` into ``output_pcap`` and return packet count."""
        self.reset()
        output_path = Path(output_pcap)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        writer = PcapWriter(str(output_path), append=append, sync=sync)
        written = 0
        try:
            with pcap_reader(input_pcap) as reader:
                for packet in reader:
                    if packet.haslayer(IP):
                        ip_layer = packet.getlayer(IP)
                        src, dst = ip_layer.src, ip_layer.dst
                        new_src, new_dst = self.anonymize_pair(src, dst)
                        if new_src != src or new_dst != dst:
                            ip_layer.src = new_src
                            ip_layer.dst = new_dst
                            if "chksum" in ip_layer.fields:
                                del ip_layer.chksum
                    writer.write(packet)
                    written += 1
        finally:
            writer.close()

        if tracking_file:
            self._write_tracking(tracking_file)

        return written

    # internal helpers -------------------------------------------------

    def _anonymize_ip(self, ip: str, *, counterpart: str) -> str:
        if not self._is_public_ip(ip):
            return ip

        replacement = self._public_to_replacement.get(ip)
        if replacement is None:
            subnet = self._private_to_subnet.get(counterpart, self.default_subnet)
            replacement = self._generate_ip(subnet)
            self._public_to_replacement[ip] = replacement

        if counterpart in self._private_to_subnet:
            self._tracking.add((counterpart, ip, replacement))

        return replacement

    def _generate_ip(self, subnet: ipaddress._BaseNetwork) -> str:
        # Avoid network/broadcast addresses for IPv4 when possible.
        num_addresses = subnet.num_addresses
        if num_addresses <= 1:
            return str(subnet.network_address)
        if num_addresses == 2:
            return str(subnet.network_address + 1)
        low = 1 if subnet.version == 4 else 0
        high = num_addresses - 2 if subnet.version == 4 else num_addresses - 1
        offset = self._random.randint(low, high)
        return str(subnet.network_address + offset)

    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or getattr(ip_obj, "is_multicast", False)
        )

    def _write_tracking(self, tracking_file: str | Path) -> None:
        tracking_path = Path(tracking_file)
        tracking_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tracking_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["PrivateIP", "PublicIP", "ReplacementIP"])
            for row in sorted(self._tracking):
                writer.writerow(row)


def _coerce_groups(
    groups: Iterable[IPGroupMapping] | Mapping[Sequence[str], str]
) -> Iterator[IPGroupMapping]:
    if isinstance(groups, Mapping):
        for private_ips, subnet in groups.items():
            yield IPGroupMapping(private_ips=tuple(private_ips), subnet=subnet)
    else:
        for entry in groups:
            if isinstance(entry, IPGroupMapping):
                yield entry
            else:
                private_ips, subnet = entry  # type: ignore[misc]
                yield IPGroupMapping(private_ips=tuple(private_ips), subnet=subnet)


__all__ = ["IPAnonymizer", "IPGroupMapping"]
