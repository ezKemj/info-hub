import os, re, json, time, hashlib, html, traceback
from pathlib import Path
from datetime import datetime, timedelta, timezone
import feedparser
import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "sources"
RULE_DIR = ROOT / "rules"
DATA_DIR = ROOT / "data"
STATE_DIR = ROOT / "state"
LOG_DIR = ROOT / "logs"
PUB_DIR = ROOT / "public"

TIMEOUT = 20
USER_AGENT = "InfoHubBot/1.0 (+https://github.com)"
DEFAULT_TTL_DAYS = 30
FAIL_DISABLE_AFTER = 3
DISABLE_DURATION = timedelta(hours=24)

def now_utc():
    return datetime.utcnow().replace(tzinfo=timezone.utc)

def read_lines(p: Path):
    if not p.exists(): return []
    return [x.strip() for x in p.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip() and not x.strip().startswith("#")]

def load_sources():
    core = read_lines(SRC_DIR / "core.txt")
    secondary = read_lines(SRC_DIR / "secondary.txt")
    return core, secondary

def load_rules():
    return {
        "whitelist": set(read_lines(RULE_DIR / "whitelist.txt")),
        "blacklist": set(read_lines(RULE_DIR / "blacklist.txt")),
        "persistent_domains": set(read_lines(RULE_DIR / "persistent_domains.txt")),
    }

def domain_of(url):
    m = re.match(r"^https?://([^/]+)", url.strip(), flags=re.I)
    return m.group(1).lower() if m else ""

def html_to_text(s):
    return BeautifulSoup(s or "", "lxml").get_text(" ", strip=True)

def normalize_entry(src_url, e):
    title = (getattr(e, "title", "") or "").strip()
    link  = (getattr(e, "link" , "") or "").strip()
    summary_html = getattr(e, "summary", "") or getattr(e, "description", "")
    summary_text = html.unescape(html_to_text(summary_html))
    pub_raw = getattr(e, "published", "") or getattr(e, "updated", "") or ""
    try:
        pub_dt = dateparser.parse(pub_raw)
        if not pub_dt.tzinfo:
            pub_dt = pub_dt.replace(tzinfo=timezone.utc)
        pub_iso = pub_dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pub_iso = now_utc().isoformat()

    sdom = domain_of(src_url)
    sig_src = f"{title}|{link}|{sdom}"
    sig = hashlib.sha1(sig_src.encode("utf-8")).hexdigest()
    return {
        "id": sig,
        "title": title,
        "link": link,
        "summary": summary_text,
        "published": pub_iso,
        "source": src_url,
        "source_domain": sdom
    }

def pass_filters(item, rules):
    text = f"{item['title']} {item['summary']}"
    wl = rules["whitelist"]
    bl = rules["blacklist"]
    if wl and not any(k in text for k in wl):
        return False
    if bl and any(k in text for k in bl):
        return False
    return True

def is_persistent(item, rules):
    dom = item["source_domain"]
    return any(dom == d or dom.endswith("." + d) for d in rules["persistent_domains"])

def is_expired(item, rules, now):
    if is_persistent(item, rules): return False
    ttl = timedelta(days=DEFAULT_TTL_DAYS)
    try:
        pub = dateparser.parse(item["published"])
        if not pub.tzinfo: pub = pub.replace(tzinfo=timezone.utc)
    except Exception:
        pub = now
    return (now - pub) > ttl

def safe_request(url):
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        return resp
    except requests.exceptions.Timeout:
        # 超时重试一次
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        return resp

def fetch_feed(url):
    try:
        resp = safe_request(url)
        content = resp.text
        feed = feedparser.parse(content)
        if feed.bozo and not feed.entries:
            return [], f"parse error: {getattr(feed, 'bozo_exception', '')}"
        return feed.entries, None
    except Exception as e:
        return [], f"{type(e).__name__}: {str(e)}"

def should_skip_by_state(state, url, now):
    rec = state.get(url)
    if not rec: return False, None
    disabled_until = rec.get("disabled_until")
    if disabled_until:
        try:
            du = dateparser.parse(disabled_until)
        except Exception:
            du = now
        if now < du:
            return True, f"disabled_until {disabled_until}"
    return False, None

def update_state_on_result(state, url, ok, error_msg, now):
    rec = state.get(url, {
        "last_success": None, "last_error": None,
        "consecutive_failures": 0, "disabled_until": None
    })
    if ok:
        rec["last_success"] = now.isoformat()
        rec["last_error"] = None
        rec["consecutive_failures"] = 0
        rec["disabled_until"] = None
    else:
        rec["last_error"] = f"{now.isoformat()} {error_msg}"
        rec["consecutive_failures"] = rec.get("consecutive_failures", 0) + 1
        if rec["consecutive_failures"] >= FAIL_DISABLE_AFTER:
            rec["disabled_until"] = (now + DISABLE_DURATION).isoformat()
    state[url] = rec

def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def render_index_html(items):
    lis = "\n".join(
        f'<li><a href="{i["link"]}" target="_blank">{html.escape(i["title"])}</a> '
        f'<small>({html.escape(i["source_domain"])}, {html.escape(i["published"])})</small>'
        f'<br><em>{html.escape(i.get("summary","")[:200])}</em></li>'
        for i in items[:300]
    )
    return f"""<!doctype html><meta charset="utf-8"><title>InfoHub</title>
<style>body{{font:14px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;max-width:860px
