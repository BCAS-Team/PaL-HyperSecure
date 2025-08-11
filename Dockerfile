# Base image
FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y build-essential libpq-dev netcat && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash paluser
WORKDIR /home/paluser/app

# Copy requirements first for caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Ensure entrypoint is executable
RUN chmod +x /home/paluser/app/entrypoint.sh

# Create uploads directory and set permissions
RUN mkdir -p /home/paluser/app/uploads && chown -R paluser:paluser /home/paluser/app

USER paluser

ENV FLASK_APP=app
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
