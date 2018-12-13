FROM python:2-alpine

RUN apk add iptables linux-headers gcc musl-dev libnetfilter_queue-dev libnfnetlink-dev

WORKDIR /usr/src/

COPY requirements.txt .

RUN pip install -r requirements.txt

VOLUME /data

COPY *.py ./

ENTRYPOINT ["python", "scapyre.py"]
