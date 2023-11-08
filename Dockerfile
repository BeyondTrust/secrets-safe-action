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

# Installing secrets_safe library
COPY secrets_safe /usr/src/app/secrets_safe

# it will be replace in a near future
RUN pip install secrets_safe/dist/secrets_safe_library-VERSION-py3-none-any.whl

COPY src /src

COPY main.py /main.py

ENTRYPOINT ["python", "/main.py"]
