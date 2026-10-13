import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env from backend directory, project root directory, or current working directory
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
load_dotenv(Path.cwd() / ".env")
load_dotenv()

DEFAULT_SUPABASE_URL = "https://mteofjxoercbocplahzy.supabase.co"
DEFAULT_SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im10ZW9manhvZXJjYm9jcGxhaHp5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4NjA5NTg3OSwiZXhwIjoyMTAxNjcxODc5fQ.FqV8LDPz5hMESqKO6pVs6Mvgab4nYcIHuGfxarLfrt8"

SUPABASE_URL = os.environ.get("SUPABASE_URL") or DEFAULT_SUPABASE_URL
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or DEFAULT_SUPABASE_KEY
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

CIRCL_BASE_URL = "https://cve.circl.lu/api"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

ASSET_WEIGHT = {
    "low": 1.0,
    "medium": 1.5,
    "high": 2.0,
    "critical": 3.0,
}

EXPOSURE_MULTIPLIER = {
    "restricted": 1.0,
    "internal": 1.5,
    "internet_facing": 2.5,
}

KEV_MULTIPLIER_LISTED = 1.5
KEV_MULTIPLIER_UNLISTED = 1.0

ZONE_WEIGHT_BONUS = {
    "internal": 1.2,
    "external": 1.0,
}

BLAST_RADIUS_MIN = 1.0
BLAST_RADIUS_MAX = 2.0
BLAST_RADIUS_PER_RELATED_ASSET = 0.1
BLAST_RADIUS_REACHABILITY_MODE = "same_subnet"

COMPOSITE_SCORE_MIN = 0
COMPOSITE_SCORE_MAX = 100

EPSS_HIGH_THRESHOLD = 0.5
EPSS_MEDIUM_THRESHOLD = 0.1
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0

SLA_HOURS = {
    "P1": 72,
    "P2": 168,
    "P3": 336,
    "P4": 720,
}

SCAN_RATE_LIMIT_PER_HOUR = 10
SCAN_STATUS_VALUES = ["queued", "running", "ingesting", "scoring", "complete", "failed"]

TARGET_TYPES = ["domain", "ip", "cidr", "cloud_project"]
