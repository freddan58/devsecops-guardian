FROM python:3.12-slim

WORKDIR /app

# Install shared agent dependencies first
COPY agents/scanner/requirements.txt /tmp/scanner-reqs.txt
COPY agents/analyzer/requirements.txt /tmp/analyzer-reqs.txt
COPY agents/fixer/requirements.txt /tmp/fixer-reqs.txt
COPY agents/compliance/requirements.txt /tmp/compliance-reqs.txt
COPY agents/risk-profiler/requirements.txt /tmp/risk-profiler-reqs.txt

RUN pip install --no-cache-dir \
    -r /tmp/scanner-reqs.txt \
    -r /tmp/analyzer-reqs.txt \
    -r /tmp/fixer-reqs.txt \
    -r /tmp/compliance-reqs.txt \
    -r /tmp/risk-profiler-reqs.txt

# Install MCP server dependencies (required by github_client.py → server.py)
COPY mcp-servers/github/pyproject.toml /tmp/mcp-server/pyproject.toml
RUN pip install --no-cache-dir "mcp[cli]>=1.0.0"

# Install API dependencies
COPY api/requirements.txt /tmp/api-reqs.txt
RUN pip install --no-cache-dir -r /tmp/api-reqs.txt

# Copy application code
COPY agents/ /app/agents/
COPY mcp-servers/ /app/mcp-servers/
COPY api/ /app/api/

# Create reports directory
RUN mkdir -p /app/reports

WORKDIR /app/api

# Ensure pipeline logs appear in container logs immediately
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
