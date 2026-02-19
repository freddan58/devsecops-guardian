"""
DevSecOps Guardian - API Gateway Configuration
"""

import os
from dotenv import load_dotenv

# Load .env from api/ directory
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Server
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# CORS - allowed origins (comma-separated)
CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io"
).split(",")

# Paths
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENTS_DIR = os.path.join(ROOT_DIR, "agents")
REPORTS_DIR = os.path.join(ROOT_DIR, "reports")

# Agent directories
SCANNER_DIR = os.path.join(AGENTS_DIR, "scanner")
ANALYZER_DIR = os.path.join(AGENTS_DIR, "analyzer")
FIXER_DIR = os.path.join(AGENTS_DIR, "fixer")
RISK_PROFILER_DIR = os.path.join(AGENTS_DIR, "risk-profiler")
COMPLIANCE_DIR = os.path.join(AGENTS_DIR, "compliance")

# Pipeline defaults
DEFAULT_SCAN_PATH = os.getenv("DEFAULT_SCAN_PATH", "demo-app")
PIPELINE_TIMEOUT = int(os.getenv("PIPELINE_TIMEOUT", "600"))  # 10 min max

# Azure Table Storage (persistence)
AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "")
STORAGE_TABLE_NAME = os.getenv("STORAGE_TABLE_NAME", "scans")
