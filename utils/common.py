import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Config values
SITE_BASE = os.getenv("ATLASSIAN_SITE_BASE", "https://your-domain.atlassian.net")
ORG_ID = os.getenv("ATLASSIAN_ORG_ID", "")
PAGE_SIZE = int(os.getenv("ATLASSIAN_PAGE_SIZE", "500"))
API_TIMEOUT = int(os.getenv("ATLASSIAN_API_TIMEOUT", "20"))
ATLASSIAN_API_BASE = os.getenv("ATLASSIAN_API_BASE", "https://api.atlassian.com")

# HTTP connection pool settings
HTTP_POOL_SIZE = int(os.getenv("ATLASSIAN_HTTP_POOL_SIZE", "20"))
HTTP_MAX_RETRIES = int(os.getenv("ATLASSIAN_HTTP_MAX_RETRIES", "5"))
HTTP_BACKOFF_FACTOR = float(os.getenv("ATLASSIAN_HTTP_BACKOFF_FACTOR", "0.5"))

# Backwards compatibility aliases
ATLASSIAN_ORG_ID = ORG_ID

# Auth helper
def get_auth():
    email = os.getenv("ATLASSIAN_EMAIL")
    api_token = os.getenv("ATLASSIAN_API_TOKEN")
    if not email or not api_token:
        raise Exception("ATLASSIAN_EMAIL and ATLASSIAN_API_TOKEN must be set in env")
    return (email, api_token)
