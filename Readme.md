# DeadSpace14 Ban Checker Bot

A specialized Discord bot designed to detect and monitor potential ban evasion on DeadSpace14 game servers. This tool
helps administrators and moderators identify players who may be attempting to bypass bans by analyzing connection
patterns, hardware IDs, IP addresses, and user behavior.

## Features

- **Ban Bypass Detection**: Advanced algorithms to detect potential ban evasion using multiple detection methods:
    - HWID matching (high confidence)
    - IP address + time correlation (medium confidence)
    - IP address matching (low confidence)

- **Player Analysis**: Detailed player information including:
    - Ban history and reasons
    - Associated IP addresses and HWIDs
    - Connection patterns
    - Nickname variations

- **Complaint Integration**: Cross-references player information with complaint channels to identify problematic players

- **Rich Reporting**:
    - JSON reports for data processing
    - Interactive HTML reports with filtering and sorting capabilities
    - Visual confidence indicators and status badges

- **Multi-server Support**: Monitor multiple SS14 communities and complaint channels

## Installation

### Requirements

- Python 3.8+
- Discord account with user token
- Admin access to DeadSpace14 admin panel

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/deadspace14-ban-checker.git
   cd deadspace14-ban-checker
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure your credentials (see Configuration section below)

## Configuration

Edit the `config.py` file with your credentials and channel IDs:

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

# Additional settings
COMPLAINT_MESSAGE_HISTORY_LIMIT = 70000  # Number of messages to cache
```

## Usage

### Running the Bot

Execute the main script to start the bot:

```
python main.py
```

By default, the bot will:

- Log in to Discord using your user token
- Connect to the admin panel
- Check recent ban hits (default: 1 page)
- Generate a report of potential ban bypass attempts

### Command Line Arguments

The default settings can be customized in the `main.py` file:

```python
# Modify these parameters to change the bot's behavior
message_limit = 2  # Number of messages to scan
username = None  # Search for a specific username
check_ban_bypass = True  # Enable ban bypass checking
ban_bypass_pages = 1  # Number of ban hit pages to check
log_file = None  # Log file path (None for stdout)
log_level = "INFO"  # Logging level
html_report_filename = "ban_bypass_report.html"  # HTML report filename
```

## Report Types

### JSON Reports

JSON reports are saved as `scan_report.json` and contain detailed information about players, their connections, ban
status, and potential bypass attempts.

### HTML Reports

HTML reports provide an interactive interface with:

- Dashboard summary with key statistics
- Filtering options (confidence level, VPN detection, HWID status)
- Sorting capabilities (by name, ban count, confidence)
- Detailed player information with tabbed interfaces
- Evidence for potential bypassers
- Copy functionality for IPs and HWIDs

## Detection Methods

The system uses multiple methods to identify potential ban evasion:

1. **HWID Match (100% confidence)**
    - Different accounts sharing identical hardware IDs

2. **IP + Close Time Match (40-50% confidence)**
    - Different accounts connecting from the same IP address within 5-10 minutes of a ban

3. **IP + Time Match (20-30% confidence)**
    - Different accounts connecting from the same IP address within 30 minutes of a ban

4. **IP Match (1-10% confidence)**
    - Different accounts sharing the same IP address

## Architecture

The bot is built with a modular architecture:

- **Services**: Separate components for Discord, admin panel, reporting, etc.
- **Models**: Data structures for players, ban hits, complaints, etc.
- **Core**: Analysis and scanning logic
- **Utils**: Helper functions and utilities

## Troubleshooting

### Common Issues

- **Discord Connection Issues**: Ensure your token is valid and the bot has necessary permissions
- **Admin Panel Access**: Verify your admin credentials and ensure the admin panel is accessible
- **Rate Limiting**: The bot uses rate limiting to avoid overwhelming the admin API

### Logging

The bot logs detailed information about its operations. Use the `log_level` parameter to adjust verbosity.

## License

This project is intended for legitimate server administration purposes only. Misuse to facilitate ban evasion is
strictly prohibited.

## Disclaimer

This tool is designed for server administrators to maintain server integrity and is not intended to be used for
harassment or targeting individual players unfairly.