# Dockerfile — explain-cli API server
# Build:  docker build -t explain-cli .
# Run:    docker run -p 8000:8000 explain-cli

FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir \
    click \
    rich \
    bashlex \
    fastapi \
    "uvicorn[standard]" \
    httpx

# Copy source code
COPY explain/ ./explain/
COPY api.py .

# Create config directory
RUN mkdir -p /root/.explain

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/health')"

# Run the API server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
