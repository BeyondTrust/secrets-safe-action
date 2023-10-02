# base image  
FROM python:3.10.13-alpine

# setup environment variable  
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN python -m pip install --upgrade pip

WORKDIR /usr/src/app

# Copying certificate
COPY certificate /usr/src/app/certificate

# Installing requirements from requirements.txt file
COPY requirements.txt /usr/src/app
RUN pip install -r requirements.txt

# Installing secrets_safe library
COPY secrets_safe /usr/src/app/secrets_safe
RUN pip install secrets_safe/dist/dist/secrets_safe_package-0.0.0-py3-none-any.whl

COPY main.py /main.py

ENTRYPOINT ["python", "/main.py"]
