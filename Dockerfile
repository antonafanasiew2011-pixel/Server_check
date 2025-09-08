FROM python:3.11-slim

# System deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -ms /bin/bash appuser

WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Expose port
EXPOSE 8000

# Ensure sqlite file dir is writable and exists
RUN mkdir -p /app \
 && chown -R appuser:appuser /app

USER appuser

# Environment defaults (can be overridden)
ENV PYTHONUNBUFFERED=1 \
    UVICORN_WORKERS=2 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000

# Run the API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


