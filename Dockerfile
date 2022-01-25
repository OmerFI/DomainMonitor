FROM python:3.9
WORKDIR /opt/domainmonitor
RUN mkdir -p /opt/domainmonitor

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libffi-dev \
    libssl-dev \
    git \
    dos2unix \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/domainmonitor/

RUN pip install -r requirements.txt --no-cache-dir

COPY . /opt/domainmonitor/

RUN adduser \
    --disabled-login \
    -u 1001 \
    --gecos "" \
    --shell /bin/bash \
    domainmonitor

RUN dos2unix /opt/domainmonitor/docker-entrypoint.sh

RUN chmod +x /opt/domainmonitor/docker-entrypoint.sh \
    && chown -R 1001:1001 /opt/domainmonitor

USER 1001
EXPOSE 8000
ENTRYPOINT [ "/opt/domainmonitor/docker-entrypoint.sh" ]
