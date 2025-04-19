FROM python:3.7-alpine
LABEL org.opencontainers.image.authors="Vishal Grover"

ADD requirements.txt /tmp
RUN apk add -U --virtual .bdep \
    build-base \
    gcc \
    && \
    pip install -r /tmp/requirements.txt && \
    apk del .bdep

ADD . /app
VOLUME /data

WORKDIR /app

EXPOSE 8080

CMD ["./service.py", "--refresher", "--consumer", "--interface", "--create_db", "--cfg", "/data/config.ini"]
