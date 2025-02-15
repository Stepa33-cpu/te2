FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -r -s /bin/bash appuser

# Create necessary directories with correct permissions
RUN mkdir -p /app/logs \
    /app/secure_storage/blockchain/metadata \
    /app/secure_storage/blockchain/logs && \
    chown -R appuser:appuser /app && \
    chmod -R 755 /app/secure_storage

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Start with proper logging and increased timeout
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--timeout", "300", \
     "--log-level", "debug", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "--preload", \
     "--reload", \
     "--max-requests", "1000", \
     "--limit-request-line", "8190", \
     "--limit-request-field_size", "8190", \
     "app1:app"] 