# base image  
FROM python:3.11-alpine

# setup environment variable  
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN python -m pip install --upgrade pip

RUN apk update && apk upgrade -i -a --update-cache

WORKDIR /usr/src/app

# Installing requirements from requirements.txt file
COPY requirements.txt /usr/src/app
RUN pip install -r requirements.txt



COPY src /src

COPY main.py /main.py

ENTRYPOINT ["python", "/main.py"]
