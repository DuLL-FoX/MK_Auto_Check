DISCORD_USER_TOKEN = "USER_TOKEN"

# Target channel ID for monitoring
TARGET_CHANNEL_ID = 1315754807595761695

# Complaint/violation channel IDs for nickname cross-checking
COMPLAINT_CHANNEL_IDS = [
    1253763748603367464,  # LUST STATION
    920845668153700393,  # SS14/Corvax (complaints)
    921508655856234537,  # SS14/Corvax (appeals)
    1173186338753884220,  # SS14/Corvax (responses)
    1226163026210717696,  # Corvax Forge
    1241728803949252618,  # SS220
    1234367190040318053,  # Imperial
    1306191493530128454,  # Corvax 18+
    1175578453567864863,  # SUNRISE
    1157956566213992468,  # Fish Station
    1112658022859284500,  # Space Stories
    1291023511607054387,  # Adventure Time
    1241692667214168166,  # Space Stories - Marines
    1264636346610221068,  # FIRE STATION 2.0
]

# Admin credentials for admin.deadspace14.net
ADMIN_USERNAME = "USERNAME"
ADMIN_PASSWORD = "PASSWORD"

COMPLAINT_MESSAGE_HISTORY_LIMIT = 70000

CLOSE_TIME_THRESHOLD_MINUTES = 10
TIME_THRESHOLD_MINUTES = 30
SUSPICIOUS_TIME_THRESHOLD_MINUTES = 60
IP_MATCH_TIMEDELTA_MINUTES = 30

# Перенесенно как default в main.py по просьбе Blade_soul
# MESSAGE_LIMIT = 10
# USERNAME = None
# CHECK_BAN_BYPASS = False
# BAN_BYPASS_PAGES = 5

# API settings
MAX_CONCURRENT_REQUESTS = 10
LOGIN_RETRY_LIMIT = 3
REQUEST_TIMEOUT = 60

# Logging settings
LOG_LEVEL = "INFO"
LOG_FILE = None

# Report settings
HTML_REPORT_FILENAME = "ban_bypass_report.html"
JSON_REPORT_FILENAME = "scan_report.json"

# Search depth settings
SEARCH_MAX_DEPTH = 3  # Maximum depth for player searches
SEARCH_LIMIT_ROOT = 20  # Number of searches at root level (depth 0)
SEARCH_LIMIT_LEVEL1 = 10  # Number of searches at level 1
SEARCH_LIMIT_LEVEL2 = 5  # Number of searches at level 2
SEARCH_LIMIT_DEFAULT = 3  # Number of searches at deeper levels

BYPASS_SEARCH_MAX_DEPTH = 2  # Maximum depth for player searches for bypass
