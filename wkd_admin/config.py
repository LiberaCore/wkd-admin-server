import os

# Paths
# Path for temporary created keyrings, required to check public OpenPGP keys
GPG_TEMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp')
# Path, where the keys are stored. WKD folder
WKD_KEY_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')

# Token for protecting the Admin API
ADMIN_TOKEN   = "12345678"

# BASE URL
BASE_URL = "http://127.0.0.1:5000"

# Enable, if you want to only accept keys for specific domains
RESTRICT_DOMAIN = True
# Only used, when RESTRICT_DOMAIN = True, add one or multiple domains, which are allowed
ALLOWED_DOMAINS = ["test.test"]

# Rate Limit
RATE_LIMIT=["240 per minute", "20 per second"]
