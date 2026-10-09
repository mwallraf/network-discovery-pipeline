# n8n for the discovery pipeline

n8n runs the daily discovery workflow: it reads the scope from Nautobot, runs
the `ndp` steps on the script server over SSH and sends notifications. This
folder starts n8n behind Caddy, which handles HTTPS.

## Setup

```bash
cp .env.example .env
openssl rand -hex 32        # paste as N8N_ENCRYPTION_KEY in .env
# set N8N_HOST, TZ, DOCKER_SUBNET, CADDY_TLS in .env
docker compose up -d
docker compose logs -f n8n  # wait for "Editor is now accessible"
```

Open `https://<N8N_HOST>/`. The first visit asks you to create the owner
account; do this right away, before anyone else can reach the page.

Store `N8N_ENCRYPTION_KEY` somewhere safe (password manager). n8n encrypts the
credentials it stores (Nautobot token, SSH key) with it; a new key makes them
unreadable.

## Certificates

- `CADDY_TLS=internal`: Caddy creates its own certificate authority. Browsers
  show a warning until they trust its root certificate:

  ```bash
  docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
  ```

  Install `caddy-root.crt` as a trusted root on the machines that use n8n (or
  have it distributed by IT).
- Certificate from your own CA: put the certificate and key in `certs/` and set
  `CADDY_TLS=/certs/n8n.crt /certs/n8n.key`, then `docker compose up -d`.

## Upgrades

Change `N8N_VERSION` in `.env`, read the n8n release notes, take a backup,
then `docker compose pull && docker compose up -d`.

## Backup

Everything n8n stores (workflows, credentials, execution history) is in the
`n8n_data` volume. Back it up together with `.env`:

```bash
docker compose stop n8n
docker run --rm -v "$(basename "$PWD")_n8n_data:/data" -v "$PWD:/backup" alpine \
  tar czf /backup/n8n-data-$(date +%Y%m%d).tgz -C /data .
docker compose start n8n
```

Export the discovery workflow to the private config repository after every
change (workflow menu → Download), so its history is in git.
