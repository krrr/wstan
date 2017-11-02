FROM python:3.5-slim
MAINTAINER Yuu Mousou <guogaishiwo@gmail.com>

EXPOSE 8080

RUN pip3 install wstan

# Add the user UID:1000, GID:1000, home at /app
RUN groupadd -r app -g 1000 && useradd -u 1000 -r -g app -m -d /app -s /sbin/nologin -c "App user" app && \
    chmod 755 /app

USER app

CMD wstan -s ws://0.0.0.0:8080 $KEY --x-forward
