# Use a slim Python image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create app directory
WORKDIR /app

# System deps (if you later need build tools / Pillow / etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Expose port (matches run_prod.py default)
EXPOSE 8000

# Default environment
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0

# Run via Waitress
CMD ["python", "run_prod.py"]
