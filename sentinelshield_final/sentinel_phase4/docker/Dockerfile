# ─────────────────────────────────────────────────────────────────
#  Dockerfile — SentinelShield Backend Container
#
#  HOW TO USE:
#  Instead of manually running uvicorn, Docker packages
#  everything into a container that runs anywhere.
#
#  Build:  docker build -t sentinelshield .
#  Run:    docker run -p 8000:8000 sentinelshield
# ─────────────────────────────────────────────────────────────────

# Use official Python 3.11 image (stable, not 3.13)
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements first (Docker caches this layer)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    sqlalchemy \
    pydantic \
    python-dotenv \
    httpx \
    scikit-learn \
    numpy \
    redis \
    websockets \
    reportlab

# Copy the entire backend into container
COPY backend/ .

# Create directory for database and ML model
RUN mkdir -p /app/ml /app/data

# Expose port 8000
EXPOSE 8000

# Start the server
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
