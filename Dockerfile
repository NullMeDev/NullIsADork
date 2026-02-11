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
ENV DORKER_GROUP_ID=""
ENV DORKER_OWNER_ID=""
ENV NOPECHA_API_KEY=""

# Data persistence
VOLUME ["/data"]

# Default command (M7: was dorker.py, now main_v3.py)
CMD ["python", "main_v3.py"]
