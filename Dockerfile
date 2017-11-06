FROM python:3.5-slim
MAINTAINER Yuu Mousou <guogaishiwo@gmail.com>

EXPOSE 8080


RUN apt-get update && apt-get install -y curl unzip

RUN pip install cryptography  # otherwise it will build from source

RUN curl https://codeload.github.com/krrr/wstan/zip/master -o 1.zip
RUN unzip 1.zip && cd wstan-master && ./setup.py install

# Add the user UID:1000, GID:1000, home at /app
RUN groupadd -r app -g 1000 && useradd -u 1000 -r -g app -m -d /app -s /sbin/nologin -c "App user" app && \
    chmod 755 /app

USER app

CMD wstan -s ws://0.0.0.0:8080 $KEY --x-forward
