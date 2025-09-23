"""Entry point for the PCAP analyzer command line interface."""
from __future__ import annotations

from pcap_analyzer.cli import main as cli_main


def main() -> int:
    """Delegate to :func:`pcap_analyzer.cli.main`."""
    return cli_main()


if __name__ == "__main__":  # pragma: no cover - convenience wrapper
    raise SystemExit(main())
