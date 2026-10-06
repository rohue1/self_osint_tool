#!/usr/bin/env python3
"""
self_osint.py - self-OSINT audit runner.

Runs whichever of these tools are on PATH against your own identifiers,
parses their output, and writes a concise Markdown report + CSV findings log:

  sherlock, maigret      -> usernames
  holehe                 -> emails (sites with an account registered)
  HIBP API v3            -> emails (breaches; needs --hibp-key or HIBP_API_KEY)
  exiftool               -> local photos (GPS / device / author metadata)
  spiderfoot / sf.py     -> passive correlation (opt-in, slow: --spiderfoot)

Google dorks and data brokers are listed as manual follow-ups; scraping
search engines and broker sites trips CAPTCHAs and violates their ToS.

Example:
  python3 self_osint.py --name "First Last" -u handle1 -u oldhandle \
      -e me@example.com -e old@example.com -i ./my_photos --spiderfoot
"""
import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
FOUND_LINE = re.compile(r"^\[\+\]\s*([^:\n]+?):\s*(https?://\S+)", re.M)
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".heic", ".tif", ".tiff", ".webp"}
SF_INTERESTING = {
    "EMAILADDR", "PHONE_NUMBER", "PHYSICAL_ADDRESS", "SOCIAL_MEDIA",
    "ACCOUNT_EXTERNAL_OWNED", "USERNAME", "HUMAN_NAME", "LEAKSITE_URL",
    "EMAILADDR_COMPROMISED", "PASSWORD_COMPROMISED", "DATE_HUMAN_DOB",
    "GEOINFO", "COMPANY_NAME",
}
SF_HIGH = {"PHONE_NUMBER", "PHYSICAL_ADDRESS", "PASSWORD_COMPROMISED",
           "DATE_HUMAN_DOB", "EMAILADDR_COMPROMISED"}


# ---------------------------------------------------------------- helpers
def recommended_action(category, risk):
    if category == "Credentials/Breach":
        return "Change affected passwords and enable MFA"
    if category == "Location":
        return "Remove GPS metadata before sharing"
    if category == "Images":
        return "Review and strip sensitive image metadata"
    if category == "Old account":
        return "Verify the account and close it if unused"
    if risk == "H":
        return "Review immediately"
    return "Review and verify"


def find_exe(*names):
    for n in names:
        path = shutil.which(n)
        if path:
            return path
    return None


def _text(x):
    if x is None:
        return ""
    return x.decode(errors="replace") if isinstance(x, bytes) else x


def run(cmd, timeout, log_path):
    """Run a command, save its output to log_path, return cleaned stdout+stderr."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = _text(p.stdout) + "\n" + _text(p.stderr)
    except subprocess.TimeoutExpired as e:
        out = _text(e.stdout) + "\n" + _text(e.stderr) + f"\n[timed out after {timeout}s]"
    except OSError as e:
        out = f"[failed to run: {e}]"
    out = ANSI.sub("", out)
    log_path.write_text(out)
    return out


class Findings:
    def __init__(self):
        self.rows = []
        self.status = {}  # tool -> "ran" / "skipped: reason"
        self._index = {}

    def add(self, tool, identifier, source, detail, category, risk):
        values = (identifier, source, detail, category)
        key = tuple(str(value).strip().casefold() for value in values)
        existing = self._index.get(key)
        if existing:
            tools = existing["tool"].split(", ")
            if tool not in tools:
                tools.append(tool)
                existing["tool"] = ", ".join(tools)
            if risk == "H" or (risk == "M" and existing["risk"] == "L"):
                existing["risk"] = risk
            return
        row = dict(tool=tool, identifier=identifier, source=source,
                   detail=detail, category=category, risk=risk)
        self.rows.append(row)
        self._index[key] = row

    def by_tool(self, tool):
        return [r for r in self.rows if tool in r["tool"].split(", ")]

    def by_tools(self, *tools):
        return [r for r in self.rows
                if any(tool in r["tool"].split(", ") for tool in tools)]


# ---------------------------------------------------------------- usernames
def username_tools(usernames, raw, timeout, f):
    accounts = {}  # url -> {"site", "username", "tools": set()}

    exe = find_exe("sherlock")
    if not exe:
        f.status["sherlock"] = "skipped: not installed"
    else:
        f.status["sherlock"] = "ran"
        out_dir = raw / "sherlock"
        out_dir.mkdir(exist_ok=True)
        for u in usernames:
            out = run([exe, u, "--print-found", "--no-color", "--timeout", "15",
                       "--folderoutput", str(out_dir)],
                      timeout, raw / f"sherlock_{u}.log")
            for site, url in FOUND_LINE.findall(out):
                accounts.setdefault(url, {"site": site.strip(), "username": u,
                                          "tools": set()})["tools"].add("sherlock")

    exe = find_exe("maigret")
    if not exe:
        f.status["maigret"] = "skipped: not installed"
    else:
        f.status["maigret"] = "ran"
        out_dir = raw / "maigret"
        out_dir.mkdir(exist_ok=True)
        for u in usernames:
            out = run([exe, u, "--no-color", "--no-progressbar", "--timeout", "15",
                       "-J", "simple", "--folderoutput", str(out_dir)],
                      timeout, raw / f"maigret_{u}.log")
            hits = FOUND_LINE.findall(out)
            if not hits:  # fall back to the JSON report
                jf = out_dir / f"report_{u}_simple.json"
                if jf.exists():
                    try:
                        data = json.loads(jf.read_text())
                        for site, info in data.items():
                            st = info.get("status", {})
                            if isinstance(st, dict) and st.get("status") == "Claimed":
                                hits.append((site, info.get("url_user", "")))
                    except (json.JSONDecodeError, AttributeError):
                        pass
            for site, url in hits:
                if url:
                    accounts.setdefault(url, {"site": site.strip(), "username": u,
                                              "tools": set()})["tools"].add("maigret")

    for url, a in sorted(accounts.items(), key=lambda kv: kv[1]["site"].lower()):
        # Found by both tools = higher confidence; one tool only = verify manually
        conf = "confirmed by both" if len(a["tools"]) > 1 else f"{next(iter(a['tools']))} only - verify"
        f.add("usernames", a["username"], url, f"{a['site']} ({conf})", "Old account", "L")


# ---------------------------------------------------------------- emails
def holehe(emails, raw, timeout, f):
    exe = find_exe("holehe")
    if not exe:
        f.status["holehe"] = "skipped: not installed"
        return
    f.status["holehe"] = "ran"
    for e in emails:
        out = run([exe, e, "--only-used", "--no-color"], timeout,
                  raw / f"holehe_{e.replace('@', '_at_')}.log")
        for line in out.splitlines():
            m = re.match(r"^\[\+\]\s+(\S+\.\S+)\s*$", line.strip())
            if m:
                f.add("holehe", e, m.group(1), "account registered to this email",
                      "Old account", "M")


def hibp(emails, key, raw, f):
    if not key:
        f.status["hibp"] = "skipped: no API key (--hibp-key or HIBP_API_KEY)"
        return
    f.status["hibp"] = "ran"
    dump = {}
    for i, e in enumerate(emails):
        if i:
            time.sleep(7)  # stay under the lowest-tier rate limit
        url = ("https://haveibeenpwned.com/api/v3/breachedaccount/"
               + urllib.parse.quote(e) + "?truncateResponse=false")
        req = urllib.request.Request(url, headers={
            "hibp-api-key": key, "user-agent": "self-osint-audit"})
        breaches = None
        for _ in range(2):
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    breaches = json.loads(r.read())
                break
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    breaches = []
                    break
                if err.code == 429:
                    time.sleep(int(err.headers.get("retry-after", "10")) + 1)
                    continue
                breaches = f"HTTP {err.code}"
                break
            except urllib.error.URLError as err:
                breaches = f"error: {err.reason}"
                break
        dump[e] = breaches
        if isinstance(breaches, str):
            f.add("hibp", e, "haveibeenpwned.com", breaches, "Credentials/Breach", "?")
            continue
        for b in breaches:
            classes = b.get("DataClasses", [])
            risk = "H" if "Passwords" in classes else "M"
            f.add("hibp", e, b.get("Domain") or b.get("Name"),
                  f"{b.get('Name')} ({b.get('BreachDate')}): {', '.join(classes)}",
                  "Credentials/Breach", risk)
    (raw / "hibp.json").write_text(json.dumps(dump, indent=2))


# ---------------------------------------------------------------- images
def exif(paths, raw, timeout, f):
    exe = find_exe("exiftool")
    if not exe:
        f.status["exiftool"] = "skipped: not installed"
        return
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += [x for x in p.rglob("*") if x.suffix.lower() in IMAGE_EXT]
        elif p.is_file():
            files.append(p)
    if not files:
        f.status["exiftool"] = "skipped: no images found"
        return
    f.status["exiftool"] = "ran"
    out = run([exe, "-json", "-n", "-GPSLatitude", "-GPSLongitude", "-Make", "-Model",
               "-DateTimeOriginal", "-Software", "-Artist", "-OwnerName",
               "-SerialNumber", *map(str, files)], timeout, raw / "exiftool.log")
    try:
        data = json.loads(out[out.index("["):out.rindex("]") + 1])
    except ValueError:
        return
    for item in data:
        src = item.get("SourceFile", "?")
        if "GPSLatitude" in item and "GPSLongitude" in item:
            lat, lon = item["GPSLatitude"], item["GPSLongitude"]
            f.add("exiftool", Path(src).name, src,
                  f"GPS {lat},{lon} https://maps.google.com/?q={lat},{lon}", "Location", "H")
        extras = {k: item[k] for k in ("Make", "Model", "Artist", "OwnerName",
                                       "SerialNumber", "DateTimeOriginal") if k in item}
        if extras:
            risk = "M" if any(k in extras for k in ("Artist", "OwnerName", "SerialNumber")) else "L"
            f.add("exiftool", Path(src).name, src,
                  ", ".join(f"{k}={v}" for k, v in extras.items()), "Images", risk)


# ---------------------------------------------------------------- spiderfoot
def spiderfoot(targets, raw, timeout, f):
    exe = find_exe("spiderfoot", "sf.py")
    if not exe:
        f.status["spiderfoot"] = "skipped: not installed"
        return
    f.status["spiderfoot"] = "ran"
    for label, target in targets:
        safe = re.sub(r"[^\w.-]", "_", label)
        out = run([exe, "-s", target, "-u", "passive", "-o", "json", "-q"],
                  timeout, raw / f"spiderfoot_{safe}.log")
        try:
            events = json.loads(out[out.index("["):out.rindex("]") + 1])
        except ValueError:
            f.add("spiderfoot", label, "-", "no parseable output (see raw log)", "-", "?")
            continue
        seen = set()
        for ev in events:
            etype, data = ev.get("type", ""), str(ev.get("data", "")).strip()
            if etype not in SF_INTERESTING or not data or (etype, data) in seen:
                continue
            seen.add((etype, data))
            f.add("spiderfoot", label, ev.get("module", ""),
                  f"{etype}: {data[:200]}", etype, "H" if etype in SF_HIGH else "L")


# ---------------------------------------------------------------- manual items
def dorks(name, usernames, emails):
    q = []
    if name:
        q += [f'"{name}"', f'"{name}" filetype:pdf', f'"{name}" site:linkedin.com',
              f'"{name}" (resume OR cv)', f'"{name}" -site:linkedin.com -site:facebook.com']
    q += [f'"{u}"' for u in usernames]
    q += [f'"{e}"' for e in emails]
    return [(x, "https://www.google.com/search?q=" + urllib.parse.quote(x)) for x in q]


BROKERS = ["spokeo.com", "whitepages.com", "beenverified.com", "fastpeoplesearch.com",
           "truepeoplesearch.com", "radaris.com", "intelius.com", "peoplefinders.com"]


# ---------------------------------------------------------------- report
def write_report(args, f, out_dir, metadata):
    rows = f.rows
    high = [r for r in rows if r["risk"] == "H"]
    L = []
    L.append(f"# Self-OSINT Audit - {metadata['started_at']}\n")
    L.append("## Scan metadata\n")
    L.append(f"- Started: {metadata['started_at']}")
    L.append(f"- Completed: {metadata['completed_at']}")
    L.append(f"- Duration: {metadata['duration_seconds']:.1f} seconds")
    L.append(f"- Python: {sys.version.split()[0]}")
    L.append(f"- Findings after deduplication: {len(rows)}\n")

    L.append("## Identifiers searched\n")
    if args.name:
        L.append(f"- Name: {args.name}")
    L.append(f"- Usernames: {', '.join(args.username) or '-'}")
    L.append(f"- Emails: {', '.join(args.email) or '-'}")
    L.append(f"- Images: {', '.join(args.images) or '-'}\n")

    L.append("## Tool status\n")
    L.append("| Tool | Status | Findings |\n|---|---|---|")
    for tool, st in f.status.items():
        n = len(f.by_tool(tool))
        L.append(f"| {tool} | {st} | {n if st == 'ran' else '-'} |")
    L.append("")

    L.append(f"## High-risk items ({len(high)})\n")
    L += [f"- **{r['category']}** - {r['identifier']}: {r['detail']}" for r in high] or ["- None found by automated tools."]
    L.append("")

    sections = [
        (("sherlock", "maigret"), "Accounts found by username (sherlock/maigret)"),
        (("holehe",), "Sites with an account registered to your emails (holehe)"),
        (("hibp",), "Breaches (HIBP)"),
        (("exiftool",), "Photo metadata (exiftool)"),
        (("spiderfoot",), "SpiderFoot passive results"),
    ]
    for tools, title in sections:
        items = f.by_tools(*tools)
        if not items:
            continue
        L.append(f"## {title} ({len(items)})\n")
        L.append("| Identifier | Source | Detail | Risk |\n|---|---|---|---|")
        for r in items:
            detail = r["detail"].replace("|", "/")
            L.append(f"| {r['identifier']} | {r['source']} | {detail} | {r['risk']} |")
        L.append("")

    L.append("## Manual follow-ups\n")
    L.append("Google dorks (also try Bing, DuckDuckGo, Yandex):\n")
    L += [f"- [{q}]({u})" for q, u in dorks(args.name, args.username, args.email)]
    L.append("\nReverse image search your profile photos: Google Lens, TinEye, Yandex, PimEyes.")
    L.append("Download your photos back *from each platform* and run exiftool on those copies "
             "to confirm the platform strips metadata.\n")
    L.append("Data brokers to check for name + city: " + ", ".join(BROKERS) + "\n")
    L.append(f"Raw tool output: `{out_dir / 'raw'}`\n")

    (out_dir / "report.md").write_text("\n".join(L))

    with open(out_dir / "findings.csv", "w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["tool", "identifier", "source", "detail", "category",
                        "risk", "action", "status", "scan_started", "scan_completed"],
        )
        w.writeheader()
        for r in rows:
            w.writerow({
                **r,
                "action": recommended_action(r["category"], r["risk"]),
                "status": "open",
                "scan_started": metadata["started_at"],
                "scan_completed": metadata["completed_at"],
            })


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Self-OSINT audit runner")
    ap.add_argument("--name", default="", help="your full name")
    ap.add_argument("-u", "--username", action="append", default=[], help="repeatable")
    ap.add_argument("-e", "--email", action="append", default=[], help="repeatable")
    ap.add_argument("-i", "--images", action="append", default=[],
                    help="image file or folder, repeatable")
    ap.add_argument("--hibp-key", default=os.environ.get("HIBP_API_KEY", ""))
    ap.add_argument("--spiderfoot", action="store_true", help="also run SpiderFoot (slow)")
    ap.add_argument("--timeout", type=int, default=600, help="per-command timeout, seconds")
    ap.add_argument("--sf-timeout", type=int, default=1800, help="SpiderFoot timeout per target")
    ap.add_argument(
        "-o", "--out", default="osint_audit",
        help="output directory; repeated runs overwrite this run's report and raw logs",
    )
    args = ap.parse_args()

    if not (args.name or args.username or args.email or args.images):
        ap.error("give at least one of --name, -u, -e, -i")

    started_at = datetime.now().astimezone()
    started_clock = time.monotonic()
    out_dir = Path(args.out)
    raw = out_dir / "raw"
    if raw.exists():
        shutil.rmtree(raw)
    raw.mkdir(parents=True, exist_ok=True)
    f = Findings()

    steps = []
    if args.username:
        steps.append(("usernames", lambda: username_tools(args.username, raw, args.timeout, f)))
    if args.email:
        steps.append(("holehe", lambda: holehe(args.email, raw, args.timeout, f)))
        steps.append(("hibp", lambda: hibp(args.email, args.hibp_key, raw, f)))
    if args.images:
        steps.append(("exiftool", lambda: exif(args.images, raw, args.timeout, f)))
    if args.spiderfoot:
        targets = ([(args.name, f'"{args.name}"')] if args.name else []) \
            + [(u, f'"{u}"') for u in args.username] + [(e, e) for e in args.email]
        steps.append(("spiderfoot", lambda: spiderfoot(targets, raw, args.sf_timeout, f)))

    for label, fn in steps:
        print(f"[*] {label} ...", flush=True)
        fn()

    completed_at = datetime.now().astimezone()
    metadata = {
        "started_at": started_at.isoformat(timespec="seconds"),
        "completed_at": completed_at.isoformat(timespec="seconds"),
        "duration_seconds": time.monotonic() - started_clock,
    }
    write_report(args, f, out_dir, metadata)
    print(f"[+] {len(f.rows)} findings, "
          f"{sum(r['risk'] == 'H' for r in f.rows)} high-risk")
    print(f"[+] Report:   {out_dir / 'report.md'}")
    print(f"[+] CSV log:  {out_dir / 'findings.csv'}")
    for tool, st in f.status.items():
        if st != "ran":
            print(f"[-] {tool}: {st}")


if __name__ == "__main__":
    main()
