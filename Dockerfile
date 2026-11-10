FROM denoland/deno:bin AS deno
FROM python:3.11-slim
COPY --from=deno /deno /usr/local/bin/deno
RUN apt-get update && apt-get install -y --no-install-recommends aria2 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --upgrade flask requests cryptography --pre "yt-dlp[default]"
RUN useradd -m -u 1000 user
USER user
WORKDIR /home/user/app
COPY --chown=user . .
CMD ["python", "vault_leech.py"]
