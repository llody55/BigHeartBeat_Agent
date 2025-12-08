FROM python:3.12-slim

LABEL maintainer="llody"

ENV PIP_CACHE_DIR /app/.cache

WORKDIR /app

COPY . /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev curl && \
    pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/ && \
    apt-get remove -y gcc python3-dev && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /app/.cache
    
RUN useradd -m -u 1000 llody && \
    mkdir -p /app/conf /app/data && \
    chown -R llody:llody /app

USER llody

ENV HOST_ID_FILE_PATH="/app/data/host_id"

VOLUME /app/data

CMD ["python3","client.py"]
