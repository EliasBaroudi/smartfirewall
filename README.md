# SmartFireWall

SmartFireWall is a network traffic analyzer and firewall rules generator. Its main purpose is to **help with firewall configuration**. It reads PCAP/PCAPNG files, analyzes network flows, generates CSV/SQLite/Elasticsearch outputs, and can visualize traffic using AfterGlow.  

!! The generated graphs from AfterGlow or Elasticsearch are **intended to guide your analysis**. You should perform **careful review and thoughtful consideration** of the visualizations to create coherent and effective firewall rules.

## Features

- Analyze PCAP/PCAPNG files from ./data/
- Automatically generate firewall rules
- Export results to CSV, SQLite, or Elasticsearch
- Visualize network flows with AfterGlow (Linux only)
- Fully configurable via config.py
- Docker-ready for easy deployment

## Requirements

- Python 3.11+
- Linux for AfterGlow visualization
- Docker (optional)
- Elasticsearch (if user_elastic = True)

## Installation

1. Clone the repository:
   
   git clone https://github.com/yourusername/smartfirewall.git
   cd smartfirewall

2. Install Python dependencies:
   
   pip install -r requirements.txt

3. Place your PCAP files in the ./data/ directory.

## Configuration

- Edit config.py to adjust:
  - CSV, SQLite, Elasticsearch, or AfterGlow features
  - Input/output directories
  - Thresholds for ports and servers
- Customize AfterGlow appearance in sample.properties.

## Usage

### Local Python Execution

python script.py

### Using Docker

1. Create a Docker network:

docker network create smfw_lan

2. Launch Elasticsearch via Docker Compose (Elasticsearch and smartfirewall need to be in the same network):

docker-compose up -d

3. Run SmartFireWall container:

docker run --rm --network=smfw_lan -it -v ./:/app smartfirewall python script.py

## Output

- CSV logs: ./output/YYYY-MM-DD_HH-MM/csv.csv
- SQLite database: ./output/YYYY-MM-DD_HH-MM/db.db
- Elasticsearch index: smart_fw_YYYY-MM-DD_HH-MM
- Firewall rules: ./output/YYYY-MM-DD_HH-MM/rules.txt
- AfterGlow visualization: ./output/YYYY-MM-DD_HH-MM/graph.png (Linux only)
