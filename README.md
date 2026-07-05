# Amiga Game Vault

A self-hosted ROM manager for Amiga **ADF** disk images. It ingests uploads,
identifies them against reference DATs (or by TOSEC filename), **deduplicates**
scene variants into one Edition per logical disk, and **normalizes** names to a
clean, readable form — so a sprawling pile of `A-10 Tank Killer …[h QTX][a2].adf`
variants collapses into one browsable Edition with a single canonical keeper.

- **Ingest** `.adf`, `.adz` (gzip), `.dms` (DiskMasher), and `.zip` uploads.
- **Identify** by content hash (TOSEC/WHDLoad DATs) or by parsing a TOSEC name.
- **Deduplicate** non-destructively: exact copies collapse automatically; crack/
  trainer/language variants group into an Edition with one flagged primary.
- **Normalize** to `Title-Kebab_vVer_lang_dNNofMM_uid.adf`, with the database as
  the source of truth (look up any file by its short UID, no re-upload).

> ⚠️ **No authentication.** This is a single-user, self-hosted tool. Do not
> expose it directly to untrusted networks. Keep it on `localhost`/LAN, or put a
> reverse proxy (auth + TLS) in front. It never distributes copyrighted content;
> you supply your own images.

---

## Quickstart (Docker Compose)

You need [Docker](https://docs.docker.com/get-docker/) with Compose v2. The image
is OCI-compliant and also builds with Podman/Buildah.

**1. Get the files**

```bash
git clone https://github.com/no42-org/amiga-game-vault.git
cd amiga-game-vault
```

**2. Build and start**

```bash
docker compose up -d --build
```

This builds the image from the `Dockerfile`, creates a persistent `vault-data`
volume, and starts the service on port **4500** ("A500" in leet). If that port is
taken, override it: `VAULT_HOST_PORT=4501 docker compose up -d --build`.

**3. Verify it's running**

```bash
docker compose ps          # STATUS should show "healthy"
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:4500/   # -> 200
```

**4. Open the browser UI**

Visit **http://localhost:4500** to browse, search, and review your collection.

**5. Upload an ADF** (uploads and DAT imports go through the HTTP API)

```bash
# The filename carries the identity; the request body is the raw ADF bytes.
curl -X POST \
  "http://localhost:4500/api/upload?filename=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[cr QTX].adf"))')" \
  --data-binary @"/path/to/your.adf"
```

Refresh the browser — the disk now appears as an Edition. Upload more variants
and they collapse under it automatically.

**6. Stop / update**

```bash
docker compose down          # stop (data is kept in the volume)
docker compose up -d --build # rebuild after pulling new code
```

---

## Configuration

Set via environment variables (see `compose.yml`):

| Variable          | Default          | Purpose                                            |
|-------------------|------------------|----------------------------------------------------|
| `VAULT_HOST_PORT` | `4500`           | Host port the container publishes to (compose).    |
| `VAULT_ADDR`      | `0.0.0.0:4500`   | Listen address inside the container.               |
| `VAULT_DATA`      | `/data`          | Data directory (content-addressed blobs + SQLite). |

**Port** — the published host port defaults to **4500** and is overridable without
editing files: `VAULT_HOST_PORT=4501 docker compose up -d`. To keep it host-local
only, change the mapping in `compose.yml`:

```yaml
ports:
  - "127.0.0.1:${VAULT_HOST_PORT:-4500}:4500"
```

**Data & backups** — everything lives in the `vault-data` volume under `/data`
(`blobs/` holds immutable image bytes; `vault.sqlite` holds the catalog). Back it
up by copying the volume, e.g.:

```bash
docker run --rm -v amiga-game-vault_vault-data:/data -v "$PWD":/backup \
  debian:bookworm-slim tar czf /backup/vault-backup.tar.gz -C /data .
```

---

## HTTP API (used by the UI and for scripting)

| Method & path                          | Purpose                                  |
|----------------------------------------|------------------------------------------|
| `GET  /`                               | Browser UI (browse, search, quarantine). |
| `POST /api/upload?filename=<name>`     | Upload one image (raw bytes as body).    |
| `POST /api/import-dat?source=<name>`   | Import a Logiqx DAT (XML body).          |
| `GET  /api/editions?q=&category=&language=&status=` | List/search Editions.       |
| `GET  /api/editions/{id}/variants`     | Variants of an Edition.                  |
| `GET  /api/artifact/{uid}`             | Full metadata for a UID.                 |
| `GET  /download/{uid}`                 | Download an artifact (canonical name).   |
| `GET  /export/edition/{id}`            | Download an Edition as a zip.            |
| `GET  /api/quarantine`                 | List unidentified uploads.               |
| `POST /api/quarantine/{uid}/resolve`   | Assign identity (JSON body).             |

---

## Notes

- **DiskMasher (`.dms`)** decoding uses `xdms`, which is bundled in the image.
- **Filesystem walking** (`xdftool`/amitools) is optional and not installed; the
  fuzzy inner-file matcher is a planned addition and unaffected by its absence.
- The **UID** in each filename is `sha1[:10]` — portable and self-verifying, so
  the collection can be re-indexed from the files alone if the database is lost.

## Build from source (without Docker)

Requires a Rust toolchain and a C compiler (for the bundled SQLite).

```bash
make build            # release binary at target/release/amiga-game-vault
make verify           # build + full test suite
VAULT_ADDR=127.0.0.1:4500 VAULT_DATA=./data ./target/release/amiga-game-vault
```

## License

MIT — see [LICENSE](LICENSE).
