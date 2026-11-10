FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends aria2 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask requests cryptography yt-dlp
RUN useradd -m -u 1000 user
USER user
WORKDIR /home/user/app
COPY --chown=user . .
CMD ["python", "vault_leech.py"]
