FROM python:3.11-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    APKTOOL_VERSION=2.10.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        adb \
        sqlite3 \
        binutils \
        openjdk-17-jre-headless \
        wget \
        ca-certificates \
        tar \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
        -O /usr/local/bin/apktool \
    && wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" \
        -O /usr/local/bin/apktool.jar \
    && chmod +x /usr/local/bin/apktool

RUN pip install --no-cache-dir drozer

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

ENTRYPOINT ["python", "main.py"]
