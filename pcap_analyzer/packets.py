"""Packet normalisation utilities."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Dict, Optional

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw


@dataclass(slots=True)
class PacketRecord:
    """Container for the different CSV friendly representations of a packet."""

    metadata: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None


@dataclass(slots=True)
class PacketFormatter:
    """Convert Scapy packets into dictionaries for CSV export."""

    protocol_mapping: Dict[int, str]

    def protocol_name(self, value: int | None) -> str:
        if value is None:
            return "Unknown"
        return self.protocol_mapping.get(int(value), "Unknown")

    def collect(self, packet: Packet, index: int) -> PacketRecord:
        """Return a :class:`PacketRecord` for ``packet``."""
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)
        udp_layer = packet.getlayer(UDP)

        if ip_layer is None or (tcp_layer is None and udp_layer is None):
            return PacketRecord()

        metadata = {
            "Time": float(packet.time),
            "No": index,
            "SourceIP": ip_layer.src,
            "DestinationIP": ip_layer.dst,
            "Protocol": self.protocol_name(getattr(ip_layer, "proto", None)),
            "Length": int(getattr(ip_layer, "len", 0) or 0),
        }

        if tcp_layer is not None:
            metadata.update(
                {
                    "SourcePort": int(tcp_layer.sport),
                    "DestinationPort": int(tcp_layer.dport),
                    "SequenceNumber": int(tcp_layer.seq),
                    "AcknowledgementNumber": int(tcp_layer.ack),
                }
            )
        elif udp_layer is not None:
            metadata.update(
                {
                    "SourcePort": int(udp_layer.sport),
                    "DestinationPort": int(udp_layer.dport),
                    "SequenceNumber": 0,
                    "AcknowledgementNumber": 0,
                }
            )

        raw_layer = packet.getlayer(Raw)
        payload: Optional[Dict[str, Any]] = None
        data: Optional[Dict[str, Any]] = None
        if raw_layer is not None and getattr(raw_layer, "load", None):
            encoded_payload = base64.b64encode(raw_layer.load).decode("utf-8")
            payload = {
                "No": index,
                "Length": metadata["Length"],
                "Payload": encoded_payload,
            }
            data = {
                "Time": int(metadata["Time"]),
                "Pckt_No": index,
                "Data": encoded_payload,
            }
            metadata["Load"] = encoded_payload
        else:
            metadata["Load"] = ""

        return PacketRecord(metadata=metadata, payload=payload, data=data)


__all__ = ["PacketFormatter", "PacketRecord"]
