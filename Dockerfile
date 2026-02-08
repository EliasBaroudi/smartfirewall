FROM python:3.11-slim
RUN apt update 
RUN apt install -y perl
RUN apt install -y tcpdump
RUN apt install -y libtext-csv-perl
RUN apt-get install -y graphviz

WORKDIR /app

COPY afterglow.pl .
COPY sample.properties .
COPY config.py .
COPY script.py .
COPY utils.py .
COPY requirements.txt .

RUN mkdir -p /app/data /app/output

RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python3", "script.py"]



