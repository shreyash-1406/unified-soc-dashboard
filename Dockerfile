FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m soc && mkdir -p /app/data && chown -R soc /app
USER soc
ENV SOC_DB=/app/data/soc.db USE_AI=0
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--timeout", "120", "run:app"]
