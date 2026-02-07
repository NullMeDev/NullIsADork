FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create data directory
RUN mkdir -p /data

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DORKER_BOT_TOKEN=""
ENV DORKER_CHAT_ID=""

# Data persistence
VOLUME ["/data"]

# Default command
CMD ["python", "dorker.py", "--config", "/data/config.json"]
