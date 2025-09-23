# PCAP_Analyzer

PCAP_Analyzer is a Python-based toolkit for exploring traffic captured in PCAP
files.  The project was refactored into a small, well-structured library that
focuses on streaming packet metadata to CSV files, anonymising public IP
addresses and generating small reports from the resulting datasets.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use .venv\Scripts\activate
pip install -r requirements.txt
```

## Command line interface

All functionality is now exposed through a single command line interface.  You
can invoke it either through `python -m pcap_analyzer.cli` or by running the
repository's `main.py` module directly.

```bash
python main.py --help
```

The most common sub-commands are:

| Command | Purpose |
| --- | --- |
| `metadata` | Stream packet metadata (and optionally payload/data) from a PCAP into CSV files. |
| `filter-csv` | Filter a metadata CSV by a list of IP addresses and/or CIDR subnets. |
| `split-pcap` | Split a PCAP into per-IP files. |
| `slice-pcap` | Copy packets from a PCAP until a specific epoch timestamp is reached. |
| `anonymize-csv` | Anonymise public IPs in a metadata CSV using per-subnet replacement pools. |
| `unique-ports` | List unique destination ports seen in a CSV, optionally scoped to specific source IPs. |
| `destination-ips` | List unique destinations contacted by a set of source IPs. |
| `associations` | Build a host/port association table from a metadata CSV. |
| `summary` | Produce a quick traffic summary for one or more IP addresses. |

Each command accepts `--help` to describe its arguments in more detail.

## Library structure

The refactor introduced a `pcap_analyzer` package which exposes reusable
primitives:

* :mod:`pcap_analyzer.config` – basic configuration helpers and protocol
  mappings.
* :mod:`pcap_analyzer.metadata` – stream PCAP files into CSV exports.
* :mod:`pcap_analyzer.csv_tools` – filtering and small data extraction helpers
  for metadata CSVs.
* :mod:`pcap_analyzer.anonymize` – anonymisation primitives for both CSV and
  PCAP files.
* :mod:`pcap_analyzer.pcap_ops` – higher-level operations such as slicing and
  splitting PCAPs.
* :mod:`pcap_analyzer.reporting` – small utilities for building reports such as
  association tables and traffic summaries.

The legacy modules that previously lived at the repository root now delegate to
these components to keep backwards compatibility for existing notebooks or
scripts.

## Game IP groups

Static game IP groups are centralised in :mod:`games.py` and can be imported as
simple lists or via the shared ``GAME_GROUPS`` dictionary.

## Contributing

1. Fork the repository and create a feature branch.
2. Add or update unit tests where possible.
3. Open a pull request detailing your changes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for
details.
