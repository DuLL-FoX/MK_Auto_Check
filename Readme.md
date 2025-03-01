# DeadSpace14 Ban Evasion Detector

A specialized Discord bot designed to identify and monitor potential ban evasion attempts on DeadSpace14 game servers.
This tool helps server administrators detect players attempting to bypass bans by analyzing connection patterns,
hardware identifiers, IP addresses, and behavioral patterns.

## 🔎 Features

### Advanced Detection Methods

- **Multi-tier Detection System**:
    - HWID matching (100% confidence)
    - IP address + close time correlation (40-50% confidence)
    - IP address + time correlation (20-30% confidence)
    - IP address matching (1-10% confidence)

### Comprehensive Player Analysis

- **Connection Tracking**:
    - Historical connection data
    - IP address patterns
    - Hardware ID monitoring
    - Time-based correlation analysis

### Discord Integration

- **Complaint Cross-reference**:
    - Links player information with complaint channels
    - Associates nicknames with reported violations
    - Maps player identities across multiple communities

### Rich Reporting

- **Multiple Report Formats**:
    - Interactive HTML reports with filtering and sorting
    - Structured JSON reports for data processing
    - Console log output for monitoring
    - Visual confidence indicators and status badges

### Multi-server Support

- Monitor multiple servers and complaint channels simultaneously
- Track player behavior across different DeadSpace14 communities

## 🛠️ Installation

### Requirements
- Python 3.8+
- Discord account with user token
- Admin access to DeadSpace14 admin panel

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/deadspace14-ban-detector.git
   cd deadspace14-ban-detector
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure your credentials (see Configuration section)

## ⚙️ Configuration

Edit the `config.py` file with your credentials and settings:

```python
# Discord configuration
DISCORD_USER_TOKEN = "YOUR_DISCORD_USER_TOKEN"

# Target channel for monitoring new players
TARGET_CHANNEL_ID = 1315754807595761695

# Complaint/violation channel IDs for nickname cross-checking
COMPLAINT_CHANNEL_IDS = [
    1253763748603367464,  # LUST STATION
    920845668153700393,  # SS14/Corvax (complaints)
    # Add more channels as needed...
]

# Admin credentials
ADMIN_USERNAME = "YOUR_ADMIN_USERNAME"
ADMIN_PASSWORD = "YOUR_ADMIN_PASSWORD"

# Detection sensitivity settings
CLOSE_TIME_THRESHOLD_MINUTES = 10
TIME_THRESHOLD_MINUTES = 30
SUSPICIOUS_TIME_THRESHOLD_MINUTES = 60
IP_MATCH_TIMEDELTA_MINUTES = 30

# Scan settings
CHECK_BAN_BYPASS = True
BAN_BYPASS_PAGES = 5
MESSAGE_LIMIT = 10
```

## 🚀 Usage

### Basic Operation

Run the bot with default settings:

```bash
python main.py
```

This will:

- Connect to Discord using your token
- Login to the DeadSpace14 admin panel
- Check recent ban hits (default: 5 pages)
- Generate a report of potential ban evasion attempts

### Command Line Arguments

Customize the scan with command line options:

```bash
python main.py --check-ban-bypass --ban-bypass-pages 10 --log-level DEBUG
```

Available options:

- `--message-limit`: Number of messages to scan
- `--username`: Search for a specific username
- `--check-ban-bypass`: Enable ban bypass checking
- `--ban-bypass-pages`: Number of ban hit pages to check
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR)
- `--config`: Path to alternative config file

## 📊 Report Types

### HTML Reports

The HTML report provides an interactive interface with:

- Dashboard summary with key statistics
- Filtering by confidence level, VPN detection, HWID status
- Sorting by player name, ban count, and confidence
- Detailed player information with tabbed interfaces
- Evidence panels for potential bypassers
- One-click copy functionality for IPs and HWIDs

### JSON Reports

JSON reports (`scan_report.json`) contain detailed information about:

- Player connections and ban status
- Potential bypass attempts with confidence ratings
- Associated IPs, HWIDs, and nicknames
- Ban histories and reasons

## 🔍 Detection Methodology

The system uses multiple methods to identify potential ban evasion:

1. **HWID Match (100% confidence)**
    - Different accounts sharing identical hardware IDs

2. **IP + Close Time Match (40-50% confidence)**
    - Different accounts connecting from the same IP address within 5-10 minutes of a ban

3. **IP + Time Match (20-30% confidence)**
    - Different accounts connecting from the same IP address within 30 minutes of a ban

4. **IP Match (1-10% confidence)**
    - Different accounts sharing the same IP address

## 🧱 Architecture

The bot is built with a modular architecture:

- **Services**: Separate components for Discord, admin panel, reporting
- **Models**: Data structures for players, ban hits, complaints
- **Core**: Analysis and scanning logic
- **Utils**: Helper functions and utilities

## ❗ Troubleshooting

### Common Issues

- **Discord Connection Issues**: Ensure your token is valid and the bot has necessary permissions
- **Admin Panel Access**: Verify your admin credentials and ensure the admin panel is accessible
- **Rate Limiting**: The bot uses rate limiting to avoid overwhelming the admin API

### Logging

Adjust verbosity with the `--log-level` parameter:

```bash
python main.py --log-level DEBUG
```

## 📝 License

This project is intended for legitimate server administration purposes only. Misuse to facilitate ban evasion is
strictly prohibited.

## ⚠️ Disclaimer

This tool is designed for server administrators to maintain server integrity and is not intended to be used for
harassment or targeting individual players unfairly.