"""
Risk Profiler Agent - Configuration
"""

import os
from dotenv import load_dotenv

# Load .env from project root or agents/risk-profiler/
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Azure OpenAI / Foundry Configuration
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1-mini")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")

# GitHub Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_OWNER = os.getenv("GITHUB_OWNER", "freddan58")
GITHUB_REPO = os.getenv("GITHUB_REPO", "devsecops-guardian")

# Risk Profiler Settings
RISK_PROFILER_VERSION = "1.0.0"

# Input paths (from upstream agents)
DEFAULT_SCANNER_INPUT = os.path.join(
    os.path.dirname(__file__), "..", "scanner", "reports", "scanner-output.json"
)
DEFAULT_ANALYZER_INPUT = os.path.join(
    os.path.dirname(__file__), "..", "analyzer", "reports", "analyzer-output.json"
)
DEFAULT_FIXER_INPUT = os.path.join(
    os.path.dirname(__file__), "..", "fixer", "reports", "fixer-output.json"
)

# Output path
DEFAULT_RISK_OUTPUT = os.path.join(
    os.path.dirname(__file__), "reports", "risk-profile-output.json"
)
