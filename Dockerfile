FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY cli.py .

# Create directories for models, logs, and config
RUN mkdir -p models logs config data

# Set environment variables
ENV PYTHONPATH=/app
ENV WAF_AI_LOG_LEVEL=INFO
ENV WAF_AI_HOST=0.0.0.0
ENV WAF_AI_PORT=8000

# Expose the API port
EXPOSE 8000

# Default command
CMD ["python", "cli.py", "serve"]
