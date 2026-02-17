"""
Scanner Agent - Configuration
"""

import os
from dotenv import load_dotenv

# Load .env from project root or agents/scanner/
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Azure OpenAI / Foundry Configuration
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")

# GitHub Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_OWNER = os.getenv("GITHUB_OWNER", "freddan58")
GITHUB_REPO = os.getenv("GITHUB_REPO", "devsecops-guardian")

# Scanner Settings
MAX_FILE_SIZE = 50000  # Skip files larger than 50KB
SCAN_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx",  # JavaScript/TypeScript
    ".py",                          # Python
    ".java",                        # Java
    ".cs",                          # C#
    ".go",                          # Go
    ".rb",                          # Ruby
    ".php",                         # PHP
    ".yml", ".yaml",                # IaC configs
    ".json",                        # Config files
    ".env",                         # Environment files
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", "coverage",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "package.json",  # No security findings in manifest
}
