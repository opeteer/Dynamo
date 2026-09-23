FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for cryptography and argon2
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY crypto_utils.py main.py ./
COPY templates/ ./templates/

# Create non-root user and data directory
RUN useradd -m dynamo \
    && mkdir -p /app/data \
    && chown -R dynamo:dynamo /app
USER dynamo

EXPOSE 8031

# Start server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8031"]
