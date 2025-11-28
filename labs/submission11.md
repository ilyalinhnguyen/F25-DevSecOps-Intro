## Lab 11 — Reverse Proxy Hardening (Nginx)

### Task 1 — Reverse Proxy Compose Setup
- A reverse proxy gives us a single choke point to terminate TLS, inject headers, log uniformly, and apply request-level controls without touching Juice Shop. Concentrating exposure lets us tune and patch Nginx independently while keeping the upstream container vanilla.
- Keeping the app service on the internal Docker network means only Nginx listens on host ports. Attackers cannot bypass the proxy to query the Node.js server with weaker defaults, reducing the scan surface to two hardened listener ports (8080 HTTP → 308 redirect, 8443 HTTPS).

`docker-compose ps` (run from `labs/lab11`, only Nginx exposes host ports):

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     8 minutes ago   Up 8 minutes   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     8 minutes ago   Up 8 minutes   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

### Task 2 — Security Headers
`labs/lab11/analysis/headers-https.txt` captured the HTTPS response headers below:

```
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

- **X-Frame-Options: DENY** — blocks all framing to neutralize clickjacking overlays that trick users into clicking hidden buttons.
- **X-Content-Type-Options: nosniff** — forces browsers to obey declared MIME types so uploaded scripts can’t be executed when served as text.
- **Strict-Transport-Security** — pins browsers to HTTPS for a year (with subdomains and preload), preventing SSL stripping after the first secure visit.
- **Referrer-Policy: strict-origin-when-cross-origin** — only sends the scheme/host on cross-origin requests, avoiding leakage of Juice Shop paths or tokens.
- **Permissions-Policy** — explicitly denies camera/geolocation/microphone APIs so compromised scripts can’t escalate to sensors.
- **COOP/CORP (same-origin)** — isolates the browsing context to stop speculative attacks such as XS-Leaks that rely on window references to other origins.
- **CSP-Report-Only** — documents the desired source restrictions while letting Juice Shop continue to work; we can monitor violations before enforcing CSP.

HTTP (`headers-http.txt`) shows the same defense-in-depth headers except HSTS, confirming the preload directive is emitted only after TLS termination as required.

### Task 3 — TLS, HSTS, Rate Limiting & Timeouts

#### TLS / testssl.sh summary (`labs/lab11/analysis/testssl.txt`)
- **Protocols:** Only TLS 1.2 and 1.3 are offered; SSLv2/3/TLS 1.0/1.1 are disabled, so legacy downgrade attacks like POODLE are off the table.
- **Cipher suites:** TLSv1.3 prefers `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, and `TLS_AES_128_GCM_SHA256`; TLSv1.2 falls back to `ECDHE-RSA-AES256/128-GCM-SHA384/256`. All suites provide AEAD with forward secrecy.
- **Why TLS 1.2+:** TLS 1.2 is the minimum modern browsers require, while 1.3 removes legacy handshakes, reduces round trips, and hardens against key-share probing. Dropping TLS 1.0/1.1 avoids BEAST/RC4-era pitfalls without impacting current clients.
- **Warnings:** Expected negatives stem from the self-signed localhost certificate (chain of trust, OCSP/CRL/CAA, stapling). No active vulnerabilities (Heartbleed, ROBOT, SWEET32, etc.) were detected.
- **HSTS scope:** `strict-transport-security` is present only on HTTPS (see evidence above) and absent on the HTTP 308 response, preventing browsers from caching HSTS before negotiating TLS.

#### Rate limiting evidence
`labs/lab11/analysis/rate-limit-test.txt`:

```
401
401
401
401
401
401
429
429
429
429
429
429
```

- Six login attempts succeed (but still 401 because of bad credentials) before the `limit_req` burst is exhausted; the next six calls are throttled with `429` to slow brute-force tries.
- Access log snippet (`labs/lab11/logs/access.log`):

```
172.18.0.1 - - [28/Nov/2025:07:14:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.17.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [28/Nov/2025:07:14:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.17.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [28/Nov/2025:07:14:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.17.0" rt=0.000 uct=- urt=-
```

- Nginx configuration uses `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m` with `burst=5 nodelay` on `/rest/user/login`. That effectively allows ~10 guesses per minute, enough for legitimate retries but small enough to make credential stuffing painfully slow.

#### Timeouts & proxy hardening
`labs/lab11/reverse-proxy/nginx.conf` applies:
- `client_body_timeout 10s`, `client_header_timeout 10s` — abort slowloris-style uploads where an attacker holds sockets open without sending data.
- `proxy_read_timeout 30s` / `proxy_send_timeout 30s` plus `send_timeout 10s` — fail fast if Juice Shop or clients stall, freeing worker slots for legitimate traffic.
- `proxy_connect_timeout 5s` with small `keepalive_timeout` and `client_max_body_size 2m` keep upstream resource usage predictable even under stress.

Collectively, the rate limit and timeout settings force attackers to spend more connections per guess while ensuring normal users still have room for occasional typos and slow connections.***

