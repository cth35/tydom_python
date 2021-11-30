FROM python:alpine

COPY sources/requirements.txt /opt/app/
WORKDIR /opt/app

RUN adduser -D worker && pip install -r requirements.txt

CMD ["sh"]
