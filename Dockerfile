# base image  
FROM python:3.11-alpine

# setup environment variable  
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m pip install --upgrade pip

RUN apk update && apk upgrade -i -a --update-cache

WORKDIR /usr/src/app

# Installing requirements from requirements.txt file
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

ENTRYPOINT ["python", "/usr/src/app/main.py"]