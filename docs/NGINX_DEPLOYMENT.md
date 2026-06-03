# Deploying pqfile on Ubuntu + nginx under a subdomain

This guide covers a full production deployment of the pqfile web GUI on an Ubuntu server
running nginx, with hardened TLS, privacy-preserving logging, and security headers tuned
for WebAssembly. All cryptographic operations run entirely in the visitor's browser; no
file data or key material is ever transmitted to the server.

---

## Prerequisites

- Ubuntu 22.04 LTS or 24.04 LTS
- A domain name you control (e.g. `pqfile.example.com`)
- A DNS `A` record (and optionally `AAAA`) pointing the subdomain to your server's IP
- Root or sudo access on the server
- Rust and trunk installed locally for building

---

## 1. Harden the server before anything else

### Firewall (ufw)

Allow only SSH, HTTP (for the ACME challenge), and HTTPS. Drop everything else.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp      # SSH - change this if you use a non-standard port
sudo ufw allow 80/tcp      # Let's Encrypt ACME HTTP-01 challenge
sudo ufw allow 443/tcp     # HTTPS
sudo ufw enable
sudo ufw status
```

### SSH hardening

Edit `/etc/ssh/sshd_config` and set or verify:

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
```

Reload SSH after editing:

```bash
sudo systemctl reload ssh
```

Make sure your public key is in `~/.ssh/authorized_keys` before disabling password auth
or you will lock yourself out.

### Brute-force protection (fail2ban)

```bash
sudo apt install fail2ban -y
```

Create `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = ssh
```

```bash
sudo systemctl enable --now fail2ban
```

### Automatic security updates

```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

Accept the prompt to enable automatic security updates. Configuration is at
`/etc/apt/apt.conf.d/50unattended-upgrades`.

---

## 2. Install nginx

```bash
sudo apt update
sudo apt install nginx -y
sudo systemctl enable nginx
```

---

## 3. Obtain a TLS certificate with Certbot

```bash
sudo apt install certbot python3-certbot-nginx -y
```

Run Certbot in standalone mode first (before configuring nginx, so there is no conflict):

```bash
sudo systemctl stop nginx
sudo certbot certonly --standalone -d pqfile.example.com
sudo systemctl start nginx
```

Certificates are written to `/etc/letsencrypt/live/pqfile.example.com/`.

Verify the auto-renewal timer is active:

```bash
sudo systemctl status certbot.timer
```

If it is not running:

```bash
sudo systemctl enable --now certbot.timer
```

---

## 4. Generate strong DH parameters

This is used by TLS 1.2 DHE cipher suites. Only needs to be done once per server.

```bash
sudo openssl dhparam -out /etc/nginx/dhparam.pem 4096
```

This takes several minutes. TLS 1.3 does not use these parameters, but having them
ensures forward secrecy for any TLS 1.2 clients.

---

## 5. Configure nginx

### Global hardening options

Add to the `http {}` block in `/etc/nginx/nginx.conf` (or create
`/etc/nginx/conf.d/security.conf`):

```nginx
# Hide nginx version from headers and error pages
server_tokens off;

# Rate-limiting zone shared across all virtual hosts
limit_req_zone $binary_remote_addr zone=pqfile_limit:10m rate=20r/m;

# Privacy: anonymize the last octet of IPv4 and last 80 bits of IPv6 before logging
# Replace the default log_format with one that strips the identifying portion of the IP.
log_format privacy '$remote_addr_anon - $remote_user [$time_local] '
                   '"$request" $status $body_bytes_sent '
                   '"$http_referer" "$http_user_agent"';

map $remote_addr $remote_addr_anon {
    ~(?P<ip>\d+\.\d+\.\d+)\.    $ip.0;
    ~(?P<ip>[^:]+:[^:]+):        $ip::;
    default                      0.0.0.0;
}
```

### Virtual host configuration

Create `/etc/nginx/sites-available/pqfile`:

```nginx
# Redirect all HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name pqfile.example.com;

    # Only allow the ACME challenge through on port 80
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS - the main site
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name pqfile.example.com;

    # ----------------------------------------------------------------
    # TLS
    # ----------------------------------------------------------------
    ssl_certificate     /etc/letsencrypt/live/pqfile.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pqfile.example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/pqfile.example.com/chain.pem;

    # TLS 1.2 and 1.3 only; disable 1.0 and 1.1
    ssl_protocols TLSv1.2 TLSv1.3;

    # Modern cipher suite - prefer ECDHE, disable RC4, 3DES, NULL
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
                'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
                'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
                'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;  # let clients pick; TLS 1.3 ignores this anyway

    ssl_dhparam /etc/nginx/dhparam.pem;

    # Session resumption - safe with modern TLS
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;        # disable; tickets require careful key rotation

    # OCSP stapling - server fetches and caches the revocation response
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # ----------------------------------------------------------------
    # Document root
    # ----------------------------------------------------------------
    root /var/www/pqfile;
    index index.html;

    # ----------------------------------------------------------------
    # Logging - anonymized IP, no query strings in the referer
    # ----------------------------------------------------------------
    access_log /var/log/nginx/pqfile_access.log privacy;
    error_log  /var/log/nginx/pqfile_error.log warn;

    # ----------------------------------------------------------------
    # Rate limiting
    # ----------------------------------------------------------------
    limit_req zone=pqfile_limit burst=30 nodelay;

    # ----------------------------------------------------------------
    # Security headers
    # ----------------------------------------------------------------

    # HSTS - tell browsers to use HTTPS for 1 year, include subdomains,
    # and submit to the preload list if you want.
    # Remove "preload" if you are not ready to commit the whole domain.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Prevent the page from being framed (clickjacking protection)
    add_header X-Frame-Options "DENY" always;

    # Prevent MIME-type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # Do not send Referer header when navigating away
    add_header Referrer-Policy "no-referrer" always;

    # Permissions Policy - disable browser features the app does not need
    add_header Permissions-Policy
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
        always;

    # Cross-Origin headers required for SharedArrayBuffer (used by egui for threading)
    # These also isolate the page from cross-origin data leaks (Spectre mitigations).
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;

    # Content Security Policy
    # 'wasm-unsafe-eval' is required for WebAssembly instantiation (Chrome 95+, Firefox 102+).
    # 'unsafe-inline' on style-src covers any inline styles injected by the egui/trunk runtime.
    # data: on img-src covers canvas data-URI exports used by egui for textures.
    # No 'unsafe-eval' - only the narrower 'wasm-unsafe-eval' is granted.
    add_header Content-Security-Policy
        "default-src 'self'; "
        "script-src 'self' 'wasm-unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "worker-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self';"
        always;

    # ----------------------------------------------------------------
    # MIME type for WebAssembly (ensures correct Content-Type header)
    # ----------------------------------------------------------------
    include mime.types;
    types {
        application/wasm wasm;
    }

    # ----------------------------------------------------------------
    # Static file caching
    # ----------------------------------------------------------------

    # Cache .wasm and .js assets aggressively - trunk hashes filenames on release builds
    location ~* \.(wasm|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        # Re-declare security headers - add_header does not inherit inside location blocks
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
    }

    # HTML: no cache - always fetch the latest index.html
    location = /index.html {
        expires -1;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
    }

    # ----------------------------------------------------------------
    # SPA fallback - serve index.html for any unknown path
    # ----------------------------------------------------------------
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Block access to hidden files (e.g. .git, .env)
    location ~ /\. {
        deny all;
    }
}
```

Enable the site and verify the configuration:

```bash
sudo ln -s /etc/nginx/sites-available/pqfile /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 6. Build the WASM app locally

```bash
# Install trunk if you do not already have it
cargo install trunk

# Add the WASM compile target if you do not already have it
rustup target add wasm32-unknown-unknown

# Build from inside pqfile-gui/
cd pqfile-gui
trunk build --release --public-url /
```

The output is in `pqfile-gui/dist/`. The release build hashes asset filenames (e.g.
`pqfile-abc123.wasm`), which is what makes the aggressive 1-year cache headers safe:
a new build produces new filenames, bypassing any cached copies.

---

## 7. Create the web root and deploy

On the server:

```bash
sudo mkdir -p /var/www/pqfile
sudo chown www-data:www-data /var/www/pqfile
sudo chmod 755 /var/www/pqfile
```

From your local machine:

```bash
rsync -av --delete pqfile-gui/dist/ user@yourserver.com:/var/www/pqfile/
```

The `--delete` flag removes any stale files from previous deployments.

---

## 8. DNS

Add the following records at your DNS registrar or DNS provider:

| Type | Name                   | Value           | TTL  |
|------|------------------------|-----------------|------|
| A    | pqfile.example.com     | your.server.ip  | 300  |
| AAAA | pqfile.example.com     | your::ipv6      | 300  |

### CAA record (optional but recommended)

A CAA record restricts which certificate authorities are permitted to issue certificates
for your domain. This prevents a rogue CA from issuing a certificate for your subdomain
without your knowledge.

| Type | Name               | Value                               |
|------|--------------------|-------------------------------------|
| CAA  | example.com        | 0 issue "letsencrypt.org"           |
| CAA  | example.com        | 0 issuewild ";"                     |

The second record with `";"` disables wildcard certificate issuance by any CA.

---

## 9. Verify the deployment

### Certificate and TLS grade

Run your domain through [SSL Labs](https://www.ssllabs.com/ssltest/) or use the
command-line equivalent:

```bash
curl -sI https://pqfile.example.com | grep -E "HTTP|Strict|Content-Security|X-Frame|X-Content"
```

Expected headers:

```
HTTP/2 200
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
content-security-policy: default-src 'self'; ...
```

### Security headers grade

Submit your URL to [securityheaders.com](https://securityheaders.com) for a full header
audit. The configuration above should produce an A or A+ rating.

### Check rate limiting

```bash
for i in $(seq 1 35); do curl -s -o /dev/null -w "%{http_code}\n" https://pqfile.example.com/; done
```

Requests beyond the burst limit should receive `503`.

---

## 10. Certificate renewal

Certbot installs a systemd timer that renews certificates automatically. To verify
renewal works without actually renewing:

```bash
sudo certbot renew --dry-run
```

After each renewal, certbot's post-hook reloads nginx. The default hook at
`/etc/letsencrypt/renewal-hooks/deploy/` should contain a script calling
`systemctl reload nginx`. If it does not, create one:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/bin/bash
systemctl reload nginx
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

---

## 11. Redeploying after a code update

If the self-hosted GitHub Actions runner is configured for this repository, deployment is
**automatic**: running `bump-version.ps1` pushes a version tag, which triggers
`.github/workflows/release.yml`. After the GitHub release is created, a deploy job runs on
the self-hosted runner. It downloads the WASM artifact built earlier in the same workflow,
rsyncs it to `/var/www/pqfile/` with `--delete`, and purges the Cloudflare cache
(`purge_everything`) so visitors immediately receive the new build rather than a stale
cached copy.

For manual redeployment (e.g. if the runner is offline or you are deploying from a different
machine):

```bash
# Build locally
cd pqfile-gui
trunk build --release --public-url /

# Push to server (--delete removes stale hashed assets)
rsync -av --delete dist/ user@yourserver.com:/var/www/pqfile/
```

If Cloudflare is in front of the server, also purge the cache manually from the Cloudflare
dashboard (Caching → Configuration → Purge Everything) or via the API:

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/purge_cache" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"purge_everything":true}'
```

No nginx reload is required; only static files change.

---

## 12. Privacy notes

- **No file data leaves the browser.** All encryption, decryption, and key generation
  runs inside the WebAssembly module. The nginx server only serves static assets; it
  never sees plaintext files or private keys.
- **Access logs anonymize client IPs.** The `privacy` log format defined above zeroes
  the last octet of IPv4 addresses and the last 80 bits of IPv6 addresses before writing
  to disk. This is consistent with GDPR guidance from several EU data protection
  authorities on server-side anonymization.
- **No third-party resources.** The Content Security Policy's `default-src 'self'`
  blocks any external scripts, fonts, or analytics beacons. There is no CDN, no Google
  Fonts, and no tracking pixel loaded by the page.
- **Log retention.** Consider configuring logrotate to delete nginx logs after a short
  retention window (e.g. 7 days). Edit `/etc/logrotate.d/nginx` and set `rotate 1`
  with `daily` and `maxage 7`.

---

## Summary of what is hardened and why

| Measure                          | Reason                                                              |
|----------------------------------|---------------------------------------------------------------------|
| ufw - ports 22, 80, 443 only     | Reduces attack surface to the minimum required                      |
| SSH key-only, no root login      | Eliminates credential brute-force against the most privileged account|
| fail2ban                         | Bans IPs that repeatedly fail SSH authentication                    |
| Unattended upgrades              | Applies OS security patches without manual intervention             |
| TLS 1.2/1.3 only, modern ciphers | Eliminates known-vulnerable protocol versions and weak ciphers      |
| HSTS with preload                | Forces HTTPS even on the first visit; prevents SSL stripping        |
| OCSP stapling                    | Hides client IP from the CA's OCSP server during certificate checks |
| ssl_session_tickets off          | Prevents forward-secrecy breaks from leaked ticket keys             |
| DH params (4096-bit)             | Ensures DHE cipher suites have strong key exchange parameters       |
| X-Frame-Options: DENY            | Prevents clickjacking via iframe embedding                          |
| X-Content-Type-Options: nosniff  | Prevents MIME confusion attacks                                     |
| Referrer-Policy: no-referrer     | Prevents the subdomain URL from leaking to third-party servers      |
| Permissions-Policy               | Disables browser hardware APIs the app does not use                 |
| COOP + COEP headers              | Isolates the page from cross-origin data (Spectre mitigation)       |
| CSP with wasm-unsafe-eval only   | Allows WASM instantiation without granting full eval to JS          |
| Rate limiting                    | Limits abusive request rates per IP                                 |
| server_tokens off                | Hides nginx version from attackers doing reconnaissance             |
| Anonymized access logs           | Reduces personal data stored at rest on the server                  |

---

## Service status

The live deployment is monitored at **[status.nappi.work/status/pqfile](https://status.nappi.work/status/pqfile)**. Check this page to see current uptime, incident history, and response-time metrics for the hosted web GUI.
| CAA DNS record                   | Prevents unauthorized CAs from issuing certificates for your domain |
