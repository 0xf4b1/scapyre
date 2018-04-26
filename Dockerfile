FROM python:2-alpine

WORKDIR /usr/src/

COPY *.py ./
COPY requirements.txt .

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "scapyre.py"]