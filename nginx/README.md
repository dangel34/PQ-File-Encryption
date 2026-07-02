# nginx configuration for the pqfile web app

Version-controlled copy of the production nginx config that serves the WASM/egui
web app at `pqfile.nappi.work`. Keeping it here means the site's security posture
(CSP, COOP/COEP, HSTS, cache policy, Cloudflare allowlist) is diffable, reviewable,
and can change in lockstep with the frontend - e.g. a new inline script or a new
`connect-src` origin ships in the same commit as the code that needs it.

## Layout

| Repo path | Installed to |
|---|---|
| `sites-available/pqfile` | `/etc/nginx/sites-available/pqfile` (symlinked into `sites-enabled/`) |
| `snippets/security-headers-pqfile.conf` | `/etc/nginx/snippets/security-headers-pqfile.conf` |
| `snippets/wasm-headers.conf` | `/etc/nginx/snippets/wasm-headers.conf` |
| `snippets/cloudflare-ips.conf` | `/etc/nginx/snippets/cloudflare-ips.conf` |

## Automated deploy

The `deploy` job in `.github/workflows/publish.yml` (self-hosted runner on the Pi)
installs these files, runs `nginx -t`, and reloads nginx **only if validation
passes**, so a malformed edit cannot take the site down.

The runner user needs a narrow sudoers entry. Create `/etc/sudoers.d/pqfile-deploy`
(via `visudo -f`) with, for a runner user named `github`:

```
github ALL=(root) NOPASSWD: /usr/bin/install, /usr/bin/ln, /usr/sbin/nginx, /bin/systemctl reload nginx
```

Adjust binary paths to match the host (`command -v install nginx systemctl`).

## Notes on the config

- **`add_header` inheritance**: nginx replaces (does not merge) `add_header` when a
  `location` defines its own. Every location block that sets `Cache-Control` therefore
  re-`include`s the header snippets, or the security headers would be silently dropped.
- **Dotfile deny ordering**: `location ~ /\.` is placed before the static-file regex
  locations so a dotfile ending in `.js`/`.wasm`/`.css` cannot match the long-cache
  asset block and bypass the deny.
- **CSP parity**: the CSP here is kept in sync with the `<meta http-equiv>` backstop in
  `pqfile-gui/index.html`. The meta tag is only a fallback for self-hosting from `dist/`
  without this server config; the edge policy here is authoritative and adds the headers
  a meta tag cannot express (`frame-ancestors`, HSTS, COOP/COEP).
- **`brotli_static on`** requires nginx built with the ngx_brotli module. If the host
  nginx lacks it, `nginx -t` will fail - remove that line or install the module.

## First-time bootstrap

The automated job assumes `/var/www/pqfile`, the `general` `limit_req` zone, the
`cloudflare` log format, and TLS termination at Cloudflare already exist. See
`docs/NGINX_DEPLOYMENT.md` for the full one-time server setup.
