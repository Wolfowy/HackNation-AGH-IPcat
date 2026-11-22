#!/usr/bin/env python3
"""Captures real GET responses of a running WebScan server into one JSON file (for frontend work without the stack).

Usage: python3 scripts/capture-api-samples.py [base_url] [output]
Credentials: WEBSCAN_USER / WEBSCAN_PASSWORD, else ADMIN_USERNAME / ADMIN_PASSWORD from deploy/docker/.env.
Secrets (tokens, keys, hashes, passwords) are replaced with "***". The output holds real scan data: share it deliberately.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8088").rstrip("/")
OUT = sys.argv[2] if len(sys.argv) > 2 else "api-samples/real-responses.json"
SECRET_KEY = re.compile(r"(token|secret|password|apikey|api_key|hash$|^hash|signingkey)", re.IGNORECASE)
KEEP_KEYS = {"faviconHash", "bodySha256", "inventoryHash", "manifestSha256", "fingerprintSha256", "contentHash", "sha256"}


def env_file():
    values = {}
    try:
        for line in open("deploy/docker/.env", encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                values[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        pass
    return values


def request(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw, status, ctype = r.read().decode("utf-8", "replace"), r.status, r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        raw, status, ctype = e.read().decode("utf-8", "replace"), e.code, e.headers.get("Content-Type", "")
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, raw if "json" not in ctype else None


def redact(value, key=""):
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    if isinstance(value, str) and key not in KEEP_KEYS and SECRET_KEY.search(key):
        return "***"
    return value


def items(body):
    return body.get("items", []) if isinstance(body, dict) else body if isinstance(body, list) else []


def main():
    env = env_file()
    user = os.environ.get("WEBSCAN_USER") or env.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("WEBSCAN_PASSWORD") or env.get("ADMIN_PASSWORD")
    if not password:
        sys.exit("Set WEBSCAN_PASSWORD or ADMIN_PASSWORD in deploy/docker/.env")
    status, login = request("POST", "/api/auth/login", body={"username": user, "password": password})
    if status != 200:
        sys.exit(f"Login failed: HTTP {status}")
    token = login["accessToken"]

    captured = {}

    def get(path):
        status, body = request("GET", path, token)
        captured[f"GET {path}"] = {"status": status, "body": redact(body)}
        return body

    for path in ["/api/auth/me", "/api/users/", "/api/dashboard/summary", "/api/operations", "/api/scan-limits", "/api/stats/planner",
                 "/api/settings", "/api/audit?pageSize=20", "/api/integrations/defectdojo", "/api/scope-policy", "/api/zones/",
                 "/api/networks/agent-subnets", "/api/enrollment-tokens/", "/api/tools/", "/api/assets/technologies",
                 "/api/changes", "/api/findings", "/api/jobs?pageSize=20", "/api/assets/services",
                 "/api/assets/hosts?networkDevice=true"]:
        get(path)

    networks = items(get("/api/networks/"))
    if networks:
        get(f"/api/networks/{networks[0]['id']}")

    # Topology page filters: every zone, every enabled network, a search (the first host's address prefix).
    topology = get("/api/topology") or {}
    for zone in [z["name"] for z in topology.get("zones", [])]:
        get(f"/api/topology?zone={urllib.parse.quote(zone)}")
    for network in [n for n in networks if n.get("enabled")]:
        get(f"/api/topology?networkId={network['id']}")
    if topology.get("hosts"):
        prefix = topology["hosts"][0]["address"].rsplit(".", 1)[0]
        get(f"/api/topology?search={urllib.parse.quote(prefix)}")
    agents = items(get("/api/agents/"))
    if agents:
        get(f"/api/agents/{agents[0]['agentId']}")
    schedules = items(get("/api/schedules"))
    if schedules:
        get(f"/api/schedules/{schedules[0]['id']}")
    signatures = items(get("/api/signatures"))
    if signatures:
        get(f"/api/signatures/{signatures[0]['id']}")
    workflows = items(get("/api/workflows"))
    for wf in workflows[:2]:
        get(f"/api/workflows/{wf['key']}")
        versions = items(get(f"/api/workflows/{wf['key']}/versions"))
        if versions:
            get(f"/api/workflows/{wf['key']}/versions/{versions[0]['version']}")

    hosts = items(get("/api/assets/hosts"))
    for host in hosts[:2]:
        get(f"/api/assets/hosts/{host['id']}")
        get(f"/api/observations?hostId={host['id']}&pageSize=20")

    scans = items(get("/api/scans"))
    finished = [s for s in scans if s.get("status") in ("Completed", "PartiallyCompleted")]
    for scan in (finished or scans)[:2]:
        get(f"/api/scans/{scan['id']}")
        get(f"/api/scans/{scan['id']}/jobs")
        get(f"/api/scans/{scan['id']}/events")
    if len(finished) >= 2:
        get(f"/api/scans/{finished[0]['id']}/diff?baseline={finished[1]['id']}")
    jobs = items(captured.get(f"GET /api/scans/{(finished or scans)[0]['id']}/jobs", {}).get("body")) if scans else []
    if jobs:
        get(f"/api/jobs/{jobs[0]['id']}")

    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"capturedAt": datetime.now(timezone.utc).isoformat(), "baseUrl": BASE, "responses": captured}, f, ensure_ascii=False, indent=2)
    failed = [k for k, v in captured.items() if v["status"] >= 400]
    print(f"{len(captured)} responses -> {OUT}" + (f"; non-2xx: {', '.join(failed)}" if failed else ""))


if __name__ == "__main__":
    main()
