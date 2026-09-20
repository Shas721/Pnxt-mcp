from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

POINTNXT_BASE_URL = os.getenv("POINTNXT_BASE_URL")
POINTNXT_ACCESS_TOKEN = os.getenv("POINTNXT_ACCESS_TOKEN")
POINTNXT_REFRESH_TOKEN = os.getenv("POINTNXT_REFRESH_TOKEN")
POINTNXT_REFRESH_ENDPOINT = os.getenv("POINTNXT_REFRESH_ENDPOINT", "/auth/refresh")
POINTNXT_TENANT_ID = os.getenv("POINTNXT_TENANT_ID")
