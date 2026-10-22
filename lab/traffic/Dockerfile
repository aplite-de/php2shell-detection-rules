FROM python:3.13-slim

# curl sends the request shapes; the base image ships a recent build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY traffic/lab.py /usr/local/bin/lab
ENTRYPOINT ["python3", "/usr/local/bin/lab"]
