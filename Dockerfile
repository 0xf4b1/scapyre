FROM alpine:3.11

RUN apk update && apk add python2-dev py2-pip iptables linux-headers gcc musl-dev libnetfilter_queue-dev libnfnetlink-dev

WORKDIR /usr/src/

COPY requirements.txt .

RUN pip install -r requirements.txt

VOLUME /data

COPY *.py ./

ENTRYPOINT ["python", "scapyre.py"]
