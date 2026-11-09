# One-shot Cloud Run leech

This is an on-demand Cloud Run Job, not a web server. Each execution handles one authorized download, uploads encrypted chunks to the existing Discord Vault, then exits. It does not modify the existing vault_leech.py, vault_server.py, or current Render service.

## Files
- cloud_job.py: direct HTTP(S) and BitTorrent magnet downloader plus existing Vault encryption/upload format.
- Dockerfile.cloudrun: image for the one-shot job.
- requirements-cloud.txt: Python dependencies.

## Before deploying
1. Create a Google Cloud project with billing enabled. Ask a parent/guardian to handle account and billing setup if needed.
2. Enable Cloud Run, Cloud Build, Artifact Registry, and Secret Manager APIs.
3. Store the newly rotated Discord bot token as Secret Manager secret discord-token.
4. Store the existing Vault password as Secret Manager secret vault-password. Never put either secret in GitHub or in job arguments.
5. Use the same Discord channel ID already configured for the Vault.

Cloud Run compute has a monthly free allowance, but network egress is billed separately. Uploading large files to Discord can therefore cost money, especially outside North America. Set a budget alert before running jobs. This job defaults to an 8 GiB maximum download size.

## Build image
Set PROJECT_ID and REGION to your own Google Cloud project and region:

~~~bash
gcloud config set project PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com
gcloud artifacts repositories create vault-leech --repository-format=docker --location=REGION
gcloud builds submit --tag REGION-docker.pkg.dev/PROJECT_ID/vault-leech/worker:latest --file Dockerfile.cloudrun .
~~~

## Create the job
Replace CHANNEL_ID with the existing Vault channel ID:

~~~bash
gcloud run jobs create vault-leech --image REGION-docker.pkg.dev/PROJECT_ID/vault-leech/worker:latest --region REGION --cpu 2 --memory 4Gi --task-timeout 2h --max-retries 0 --set-env-vars DISCORD_CHANNEL=CHANNEL_ID,MAX_DOWNLOAD_GB=8 --set-secrets DISCORD_TOKEN=discord-token:latest,VAULT_PASSWORD=vault-password:latest
~~~

## Run one download
In Cloud Run → Jobs → vault-leech → Execute, override the container arguments with exactly one URL:
- An authorized public HTTPS download URL.
- An authorized magnet link.

The image entrypoint already runs cloud_job.py, so the execution argument is the link only. Each execution is isolated and temporary files are deleted when it exits.

## Important limitations
- Cloud Run Jobs do not provide a permanent web page or job dashboard. This first version is run from the Cloud Console.
- Torrent peer discovery and throughput depend on the cloud network and the swarm; inbound peer connectivity is not guaranteed.
- Direct URLs must be public HTTP(S); local/private network addresses and redirects to them are blocked.
- Only download content you have permission to access.
- Do not run large jobs until billing alerts and quotas are configured.
