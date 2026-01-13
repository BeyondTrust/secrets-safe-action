# base image  
FROM python:3.11-alpine

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
#RUN mkdir -p /usr/src/tests && chown -R appuser:appgroup /usr/src/tests

WORKDIR /usr/src/app

COPY dist/beyondtrust_bips_library-2.6-py3-none-any.whl /usr/src/app

# Installing requirements from requirements.txt file
COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#RUN pip install pytest pytest-mock
RUN pip install beyondtrust_bips_library-2.6-py3-none-any.whl

# Copy source files and set proper ownership
COPY --chown=appuser:appgroup src/ src/
COPY --chown=appuser:appgroup tests/ tests/

# Switch to non-root user
USER appuser

#ENTRYPOINT ["python", "/usr/src/app/main.py"]