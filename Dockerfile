FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends snmp && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data nsm && mkdir /data && chown nsm /data
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
USER nsm
ENV NSM_DATA=/data
VOLUME /data
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
