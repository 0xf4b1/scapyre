FROM python:2-alpine

WORKDIR /usr/src/

COPY requirements.txt .

RUN pip install -r requirements.txt

VOLUME /data

COPY *.py ./

ENTRYPOINT ["python", "scapyre.py"]
