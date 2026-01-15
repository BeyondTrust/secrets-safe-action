# base image  
FROM python:3.11-alpine@sha256:25c2968770d5086249e0866482eb88c9b2eb4b0fc8918a933cc4898edec1cdb6

# setup environment variable  
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m pip install --upgrade pip

RUN apk update && apk upgrade -i -a --update-cache

# Create a non-root user
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

# Create and set ownership of the working directory
RUN mkdir -p /usr/src/app && chown -R appuser:appgroup /usr/src/app

WORKDIR /usr/src/app

# Installing requirements from requirements.txt file
COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source files and set proper ownership
COPY --chown=appuser:appgroup src/ .

# Switch to non-root user
USER appuser

ENTRYPOINT ["python", "/usr/src/app/main.py"]

