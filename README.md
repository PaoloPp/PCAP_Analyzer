# PCAP\_Analyzer

PCAP\_Analyzer is a Python-based framework developed for the UPSIDE project to analyze network traffic captured in PCAP files. It processes packet data to extract meaningful insights, aiding in network analysis and cybersecurity research.

## Features

- **Packet Anonymization**: Anonymizes sensitive information within packets to ensure privacy.
- **Association Analysis**: Identifies and analyzes relationships between different network entities.
- **Game Traffic Identification**: Detects and processes traffic related to online games.
- **Public IP Extraction**: Extracts and analyzes public IP addresses from the captured traffic.
- **Session Summarization**: Provides summaries of network sessions over specified time frames.
- **Data Visualization**: Generates plots to visualize various aspects of the network traffic.

## Requirements

- Python 3.x
- Required Python packages are listed in `requirements.txt`.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/VSecLab/PCAP_Analyzer.git
   cd PCAP_Analyzer
   ```

2. **Install Dependencies**: It's recommended to use a virtual environment to manage dependencies.

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use venv\Scripts\activate
   pip install -r requirements.txt
   ```

## Usage

1. **Prepare Your PCAP Files**: Ensure your PCAP files are accessible and note their paths.

2. **Run the Analyzer**: the Analazyer is meant to run with the python interactive option -i

   ```bash
   python main.py -i
   >>> requested_function(arg)
   ```

3. **View Results**: The analysis results, including any generated plots and summaries, will be saved in the output directory specified in the script or configuration.

## Configuration

- **Anonymization**:
  - Configure anonymization settings in `anonymization.py`.
- **Game Traffic Analysis**:
  - Update game-related IP addresses or ports in `Games_IP.xlsx`.
- **Session Summarization**:
  - Modify session parameters in `summary.py`.

## Function Descriptions

The PCAP\_Analyzer framework comprises several modules, each responsible for specific analysis tasks:

### 1. Anonymization (`anonymization.py`)

This module handles the anonymization of sensitive information within the PCAP files to ensure privacy. It replaces identifiable data such as IP addresses and MAC addresses with anonymized placeholders.

**Key Functions**:

- `anonymize_ip(ip_address)`: Replaces the given IP address with an anonymized version.
- `anonymize_mac(mac_address)`: Replaces the given MAC address with an anonymized version.

### 2. Association Analysis (`association.py`)

This module identifies and analyzes relationships between different network entities, such as IP addresses and ports, to uncover patterns and potential security issues.

**Key Functions**:

- `analyze_ip_pairs(pcap_data)`: Identifies and counts communication pairs in the network traffic.
- `analyze_port_usage(pcap_data)`: Analyzes the distribution of port usage across the captured traffic.

### 3. Game Traffic Identification (`game_traffic.py`)

This module detects and processes traffic related to online games by matching IP addresses and ports against a predefined list of known game servers.

**Key Functions**:

- `load_game_servers(file_path)`: Loads a list of known game server IPs and ports from a file.
- `identify_game_traffic(pcap_data, game_servers)`: Flags packets that are associated with known game servers.

### 4. Public IP Extraction (`public_ip_extraction.py`)

This module extracts and analyzes public IP addresses from the captured traffic, which can be useful for identifying external communications.

**Key Functions**:

- `is_public_ip(ip_address)`: Checks if the given IP address is public.
- `extract_public_ips(pcap_data)`: Extracts a list of public IP addresses from the PCAP data.

### 5. Session Summarization (`session_summary.py`)

This module provides summaries of network sessions over specified time frames, including metrics such as session duration, data transferred, and protocols used.

**Key Functions**:

- `summarize_sessions(pcap_data, time_interval)`: Summarizes network sessions within the given time interval.
- `calculate_session_metrics(session)`: Calculates metrics like duration and data volume for a given session.

### 6. Data Visualization (`visualization.py`)

This module generates plots to visualize various aspects of the network traffic, aiding in the interpretation of analysis results.

**Key Functions**:

- `plot_traffic_over_time(pcap_data)`: Creates a time series plot of network traffic volume.
- `plot_protocol_distribution(pcap_data)`: Generates a pie chart showing the distribution of different protocols in the traffic.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
