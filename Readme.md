# DeadSpace14 Ban Evasion Detector

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

A specialized Discord bot designed to identify and monitor potential ban evasion attempts on DeadSpace14 game servers.
This tool helps server administrators maintain server integrity by analyzing connection patterns, hardware identifiers,
IP addresses, and behavioral patterns to detect players attempting to circumvent bans.

## 📋 Table of Contents

- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#️-installation)
- [Configuration](#️-configuration)
- [Usage](#-usage)
- [Report Types](#-report-types)
- [Detection Methodology](#-detection-methodology)
- [Code Structure](#-code-structure)
- [Performance Considerations](#-performance-considerations)
- [Contributing](#-contributing)
- [Troubleshooting](#-troubleshooting)
- [License & Disclaimer](#-license--disclaimer)

## 🔎 Features

### Advanced Detection Methods

- **Multi-tier Detection System**:
    - HWID matching (100% confidence) - Identifies accounts sharing identical hardware IDs
    - IP address + very close time correlation (<5 min, 80-90% confidence)
    - IP address + close time correlation (5-10 min, 60-70% confidence)
    - IP address + moderate time correlation (10-30 min, 40-50% confidence)
    - IP address + distant time correlation (30-60 min, 20-30% confidence)
    - IP address matching (10-20% confidence)

### Comprehensive Player Analysis

- **Deep Connection Tracking**:
    - Historical connection data with timestamps
    - IP address usage patterns and sharing detection
    - Hardware ID monitoring and correlation
    - Time-based correlation analysis with configurable thresholds
    - Multiple account association detection

### Discord Integration

- **Complaint Cross-reference System**:
    - Links player information with complaint channels content
    - Associates nicknames with reported violations across servers
    - Maps player identities across multiple communities
    - Real-time monitoring of new player connections

### Rich Reporting

- **Multiple Report Formats**:
    - Detailed JSON reports with player relationships
    - Console log output with color-coded information
    - Visual confidence indicators and status badges
    - Ban bypass detection with success probability

### Multi-server Support

- Monitor multiple servers and complaint channels simultaneously
- Track player behavior across different DeadSpace14 communities
- Support for large-scale deployments with performance optimizations

## 🔍 How It Works

The Ban Evasion Detector operates by continuously monitoring newly connected players through Discord channel messages,
then cross-referencing these connections with the administrative panel data and past player behavior.

1. **Connection Monitoring**:
    - Scans Discord channels for "Arrived new player" messages
    - Extracts player identifiers (usernames, IPs, HWIDs)

2. **Data Collection**:
    - Queries the DeadSpace14 admin panel for detailed player information
    - Gathers historical connection data and ban history
    - Builds relationship graphs between players, IPs, and hardware IDs

3. **Pattern Analysis**:
    - Identifies shared connection patterns
    - Detects suspicious timing between bans and new connections
    - Correlates hardware identifiers and IP addresses

4. **Report Generation**:
    - Presents findings with confidence ratings
    - Provides evidence for administrative action
    - Maintains searchable record of potential evasion attempts

## 🛠️ Installation

### Requirements

- Python 3.8 or higher
- Discord account with user token
- Admin access to DeadSpace14 admin panel
- Internet connection with access to Discord API

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/deadspace14-ban-detector.git
   cd deadspace14-ban-detector
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure your credentials (see Configuration section)

5. Run the initial setup:
   ```bash
   python main.py --check-ban-bypass
   ```

## ⚙️ Configuration

The bot is configured through the `config.py` file.

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

# API settings
MAX_CONCURRENT_REQUESTS = 10
LOGIN_RETRY_LIMIT = 3
REQUEST_TIMEOUT = 60

# Logging settings
LOG_LEVEL = "INFO"
LOG_FILE = None
```

### Configuration Details

- **Discord Settings**: Set your Discord token and channel IDs for monitoring
- **Admin Credentials**: Provide login details for DeadSpace14 admin panel
- **Detection Thresholds**: Configure time windows for correlation detection
- **Scan Settings**: Control scan depth and scope
- **Performance Settings**: Adjust concurrency and request timeouts

## 🚀 Usage

### Basic Operation

Run the bot with default settings:

```bash
python main.py
```

This will:
- Connect to Discord using your token
- Login to the DeadSpace14 admin panel
- Monitor new player connections
- Generate reports of potential ban evasion attempts

### Command Line Arguments

Customize the scan with command line options:

```bash
python main.py --check-ban-bypass --ban-bypass-pages 10 --log-level DEBUG
```

Available options:

| Option                  | Description                                     |
|-------------------------|-------------------------------------------------|
| `--message-limit N`     | Number of messages to scan                      |
| `--username NAME`       | Search for a specific username                  |
| `--check-ban-bypass`    | Enable ban bypass checking                      |
| `--ban-bypass-pages N`  | Number of ban hit pages to check                |
| `--log-level LEVEL`     | Set logging level (DEBUG, INFO, WARNING, ERROR) |
| `--config PATH`         | Path to alternative config file                 |
| `--search-depth N`      | Maximum depth for player searches               |
| `--search-limit-root N` | Number of searches at root level                |

### Scan Modes

The bot has three primary scan modes:

1. **Ban Bypass Check**:
   ```bash
   python main.py --check-ban-bypass
   ```
   Scans recent ban hits to detect potential evasion attempts.

2. **Username Search**:
   ```bash
   python main.py --username "PlayerName"
   ```
   Performs a detailed investigation of a specific player.

3. **New Player Monitoring**:
   ```bash
   python main.py --message-limit 20
   ```
   Monitors recent new player announcements.

## 📊 Report Types

### JSON Reports

The JSON report (`scan_report.json`) provides machine-readable output with detailed information about:

- Player connections and ban status
- Potential bypass attempts with confidence ratings
- Associated IPs, HWIDs, and alternate nicknames
- Ban histories and reasons
- Time-based correlations
- Cross-referenced complaint data

Example structure:

```json
[
  {
    "message_id": "1234567890",
    "message_link": "https://discord.com/channels/...",
    "author_name": "BannedPlayer",
    "author_id": "user_id_string",
    "scan_time": "2023-01-01T12:00:00",
    "results": [
      {
        "initial_account": {
          "user_id": "player_id",
          "nicknames": [
            "Player1",
            "AltName1"
          ],
          "status": "banned",
          "ban_counts": 2,
          "associated_ips": {
            "192.168.1.1": [
              "Player1"
            ]
          },
          "associated_hwids": {
            "HWID1": [
              "Player1",
              "SuspiciousPlayer"
            ]
          }
        },
        "complaint_links": [
          {
            "link": "https://discord.com/channels/...",
            "content": "Player was reported for...",
            "channel": "complaints"
          }
        ]
      }
    ]
  }
]
```

### Console Output

The console output provides human-readable, color-coded information:

- **Status Indicators**:
    - 🟢 CLEAN - No ban history or suspicious activity
    - 🟡 SUSPICIOUS - Potential issues detected
    - 🔴 BANNED - Confirmed ban history

- **Connection Data**:
    - Shared IPs with ownership attribution
    - HWID sharing analysis
    - Connection timestamps and patterns

- **Evidence Panels**:
    - Complaint message extracts
    - Denied login attempts
    - Ban history details

## 🧩 Detection Methodology

The system uses a sophisticated multi-layered approach to identify potential ban evasion:

### 1. HWID Match (100% confidence)

Different accounts sharing identical hardware IDs are nearly always the same person.

**Example scenario:**

```
Player "ToxicUser" banned at 14:25
↓
Hardware ID: V2-ABCD1234
↓
Player "InnocentUser55" connected at 15:10
Same Hardware ID: V2-ABCD1234
```

### 2. IP + Close Time Match (60-90% confidence)

Different accounts connecting from the same IP address within minutes of a ban.

**Example scenario:**

```
Player "BannedPlayer" denied at 14:25 (IP: 192.168.1.1)
↓
7 minutes later
↓
Player "TotallyNew" accepted at 14:32 (IP: 192.168.1.1)
```

### 3. IP + Time Match (20-50% confidence)

Different accounts connecting from the same IP address within a larger timeframe.

### 4. IP Match (10-20% confidence)

Different accounts sharing the same IP address (may be shared networks).

The system also identifies:

- HWID erasure attempts (when expected HWID data is missing)
- VPN/proxy usage patterns
- Suspicious naming patterns

## 🧱 Code Structure

The bot is built with a modular architecture:

```
deadspace14-ban-detector/
├── admin_panel.py      # Admin panel interface
├── bot.py              # Main bot class
├── config.py           # Configuration settings
├── config_system.py    # Configuration management
├── main.py             # Entry point
├── core/
│   ├── analyzer.py     # Player data analysis
│   └── scanner.py      # Message scanning logic
├── models/
│   ├── complaint.py    # Complaint data structure
│   ├── message.py      # Discord message structure
│   ├── player.py       # Player data structure
│   └── verdict.py      # Detection verdict models
├── services/
│   ├── admin_service.py    # Admin panel API service
│   ├── cache_service.py    # Data caching service
│   ├── discord_service.py  # Discord API service
│   └── report_service.py   # Report generation
└── utils/
    ├── async_utils.py      # Async helpers
    ├── embed_utils.py      # Discord embed processing
    ├── logging_utils.py    # Logging configuration
    └── url_utils.py        # URL handling
```

### Key Components

- **Bot Class**: Coordinates Discord integration and drives the scanning process
- **Scanner**: Core scanning logic for processing messages and ban hits
- **Analyzer**: Analyzes player data to detect relationships and patterns
- **Admin Panel**: Interface to the DeadSpace14 admin system
- **Report Service**: Generates structured reports of findings

## 🚄 Performance Considerations

The bot is designed to handle large-scale deployments with performance optimizations:

- **Rate Limiting**: Intelligent rate limiting to avoid API bans
- **Connection Pooling**: Efficient HTTP connection reuse
- **Concurrency Control**: Configurable parallel request limits
- **Caching**: Multi-level caching to reduce duplicate queries
- **Incremental Processing**: Smart prioritization of search queries

For high-traffic servers, consider adjusting:

- `MAX_CONCURRENT_REQUESTS` - Control parallel API calls
- `REQUEST_TIMEOUT` - Adjust API timeout thresholds
- `SEARCH_MAX_DEPTH` - Limit recursion depth for large searches
- `COMPLAINT_MESSAGE_HISTORY_LIMIT` - Limit complaint history size

## 👥 Contributing

Contributions to improve the detector are welcome. Here's how to contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Submit a pull request

## ❗ Troubleshooting

### Common Issues

#### Discord Connection Issues

- Ensure your token is valid and the bot has necessary permissions
- Check network connectivity to Discord API servers
- Verify the target channel IDs are correct

#### Admin Panel Access

- Verify your admin credentials in the config file
- Ensure the admin panel is accessible from your network
- Check for admin panel maintenance periods

#### Rate Limiting

- If you see "Rate limit exceeded" errors, adjust `MAX_CONCURRENT_REQUESTS` down
- Consider adding delays between operations with `time.sleep()`
- Implement exponential backoff for retry operations

#### Performance Issues

- For large servers, adjust the search depth and scan limits
- Enable caching to reduce duplicate queries
- Run the bot on a dedicated machine for better performance

#### Debugging
Adjust verbosity with the `--log-level` parameter:

```bash
python main.py --log-level DEBUG
```

Logs will show detailed information about API calls, decisions, and error states.

## 📝 License & Disclaimer

This project is intended for legitimate server administration purposes only. Misuse to facilitate ban evasion is
strictly prohibited.

The tool is designed to assist server administrators in maintaining server integrity by identifying potential ban
evasion attempts. It should be used with discretion and proper authorization.

**⚠️ Disclaimer:** This tool is designed for server administrators to maintain server integrity and is not intended to
be used for harassment or targeting individual players unfairly. Always follow applicable laws and platform terms of
service when using this tool.