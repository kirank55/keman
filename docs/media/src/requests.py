"""Record what the demo proxy answers to a valid key and to leaked copies.

Usage: python3 docs/media/src/requests.py OUT.json

Run after capture.sh, from the repo root, with nothing listening on the demo
ports. It starts the mock upstream and `keman serve` on the seeded .demo/
install, sends one request per scenario (the client address goes in
X-Forwarded-For, which the demo config trusts from localhost), stops both,
and writes the requests and the real responses for the website's simulator.
"""
import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

D = ".demo"
PROXY = "http://127.0.0.1:8080"
ADMIN = "http://127.0.0.1:8081"
UPSTREAM = "127.0.0.1:18090"

CHAT = "/v1/chat/completions"

# The networks `demo geoip` writes into the demo's GeoIP databases.
NETWORKS = [
    ("203.0.113.0/25", "US", 64500), ("198.51.100.0/25", "US", 64501), ("192.0.2.0/25", "DE", 64502),
    ("203.0.113.128/25", "BR", 64510), ("192.0.2.128/25", "NL", 64511), ("198.51.100.128/25", "SG", 64512),
]


def geo(ip):
    for net, country, asn in NETWORKS:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
            return country, asn
    return None, None


# id, key file, client address, method, path, model (None for Stripe)
SCENARIOS = [
    ("allowed", "prod-api", "192.0.2.20", "POST", CHAT, "gpt-4o-mini"),
    ("network", "prod-api", "203.0.113.200", "POST", CHAT, "gpt-4o-mini"),
    ("model", "prod-api", "192.0.2.20", "POST", CHAT, "o3"),
    ("path", "billing-svc", "192.0.2.30", "POST", "/v1/payouts", None),
    ("disabled", "old-intern", "198.51.100.200", "POST", CHAT, "gpt-4o-mini"),
    ("revoked", "support-bot", "203.0.113.200", "POST", "/v1/messages", "claude-opus-4-5"),
    ("canary", "repo-decoy", "192.0.2.200", "POST", CHAT, "gpt-4o"),
]


def wait_up(url, code):
    for _ in range(100):
        try:
            urllib.request.urlopen(url, timeout=1)
        except urllib.error.HTTPError as e:
            if e.code == code:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise SystemExit(f"{url} did not come up")


def send(key, ip, method, path, model):
    token = open(os.path.join(D, "keys", key)).read().strip()
    headers = {"X-Forwarded-For": ip, "Content-Type": "application/json"}
    if path == "/v1/messages":
        headers["x-api-key"] = token
        headers["anthropic-version"] = "2023-06-01"
        body = {"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": "hi"}]}
    elif model:
        headers["Authorization"] = "Bearer " + token
        body = {"model": model, "messages": [{"role": "user", "content": "hi"}]}
    else:
        headers["Authorization"] = "Bearer " + token
        body = {"amount": 250000, "currency": "usd"}
    req = urllib.request.Request(PROXY + path, data=json.dumps(body).encode(), headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        status, rh, rb = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        status, rh, rb = e.code, e.headers, e.read()
    prefix = token.split("_")[0] + "_" + token.split("_")[1] + "_"
    country, asn = geo(ip)
    return {
        "key": key,
        "ip": ip,
        "country": country,
        "asn": asn,
        "method": method,
        "path": path,
        "auth": "x-api-key" if "x-api-key" in headers else "Authorization",
        "token": prefix + "…",
        "body": body,
        "status": status,
        "error_header": rh.get("X-Keman-Error"),
        "response": json.loads(rb),
    }


def main(out):
    procs = [subprocess.Popen([os.path.join(D, "demo"), "upstream", UPSTREAM],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    try:
        procs.append(subprocess.Popen([os.path.join(D, "keman"), "--config", os.path.join(D, "keman.yaml"), "serve"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_up(ADMIN + "/metrics", 401)
        results = {sid: send(*rest) for sid, *rest in SCENARIOS}
    finally:
        for p in procs:
            p.terminate()
            p.wait()
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    for sid, r in results.items():
        print(f"{sid:9} {r['status']} {r['error_header'] or ''}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
