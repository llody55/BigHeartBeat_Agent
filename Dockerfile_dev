FROM swr.cn-southwest-2.myhuaweicloud.com/llody/python:3.10.2-slim

LABEL maintainer="llody"

ENV PIP_CACHE_DIR /app/.cache

WORKDIR /app

COPY . /app

RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    apt-get update && \
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

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f client.py || exit 1

CMD ["python3","client.py"]
