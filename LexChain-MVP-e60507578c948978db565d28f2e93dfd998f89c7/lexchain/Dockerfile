FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create log directory
RUN mkdir -p /app/logs

# Start with proper logging
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "--log-level", "debug", "--access-logfile", "/app/logs/access.log", "--error-logfile", "/app/logs/error.log", "app1:app"] 