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
<style>body{{font:14px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;max-width:860px;margin:24px auto;padding:0 12px}}li{{margin:12px 0}}</style>
<h1>InfoHub 聚合</h1>
<p><a href="feed.xml">聚合RSS</a> | <a href="feed.json">聚合JSON</a> | <a href="status.html">源状态</a></p>
<ul>{lis}</ul>"""

def render_status_html(state):
    rows = []
    for url, rec in sorted(state.items()):
        rows.append(f"<tr><td>{html.escape(url)}</td>"
                    f"<td>{rec.get('consecutive_failures',0)}</td>"
                    f"<td>{html.escape(str(rec.get('last_success')))}</td>"
                    f"<td>{html.escape(str(rec.get('last_error')))}</td>"
                    f"<td>{html.escape(str(rec.get('disabled_until')))}</td></tr>")
    table = "\n".join(rows)
    return f"""<!doctype html><meta charset="utf-8"><title>源状态</title>
<style>table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:6px 8px}}</style>
<h1>源状态面板</h1>
<table>
<tr><th>源URL</th><th>连续失败</th><th>最后成功</th><th>最后错误</th><th>禁用至</th></tr>
{table}
</table>"""

def render_atom_feed(items, feed_title="InfoHub 聚合", feed_link="./", feed_id="infohub-agg"):
    updated = (items[0]["published"] if items else now_utc().isoformat())
    entries_xml = []
    for i in items[:200]:
        entries_xml.append(f"""
  <entry>
    <id>tag:{html.escape(i['id'])}</id>
    <title>{html.escape(i['title'])}</title>
    <link href="{html.escape(i['link'])}"/>
    <updated>{html.escape(i['published'])}</updated>
    <summary>{html.escape(i.get('summary',''))}</summary>
    <author><name>{html.escape(i.get('source_domain',''))}</name></author>
  </entry>""")
    entries = "\n".join(entries_xml)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>{feed_id}</id>
  <title>{html.escape(feed_title)}</title>
  <updated>{html.escape(updated)}</updated>
  <link href="{html.escape(feed_link)}"/>
{entries}
</feed>"""

def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    start = now_utc()
    log_name = f"build-{start.strftime('%Y%m%dT%H%M%SZ')}.log"
    log_path = LOG_DIR / log_name

    def log(msg):
        print(msg)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(msg + "\n")

    rules = load_rules()
    core_sources, secondary_sources = load_sources()

    # 判断运行频率：通过环境变量或时间判断
    # 这里简单用环境变量 RUN_GROUP 控制（在 Actions 中设置）
    run_group = os.environ.get("RUN_GROUP", "core")
    sources = core_sources if run_group == "core" else secondary_sources

    state_path = STATE_DIR / "sources.json"
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
    else:
        state = {}

    items = []
    fetched = 0
    skipped = 0

    for url in sources:
        n = now_utc()
        skip, reason = should_skip_by_state(state, url, n)
        if skip:
            log(f"SKIP [{url}] due to state: {reason}")
            skipped += 1
            continue

        log(f"FETCH [{url}] ...")
        entries, err = fetch_feed(url)
        if err:
            log(f"ERROR [{url}]: {err}")
            update_state_on_result(state, url, ok=False, error_msg=err, now=n)
            continue

        update_state_on_result(state, url, ok=True, error_msg=None, now=n)
        fetched += 1

        for e in entries:
            it = normalize_entry(url, e)
            if pass_filters(it, rules):
                items.append(it)

    # 去重
    uniq = {it["id"]: it for it in items}
    items = list(uniq.values())

    # 加载上次 latest，合并未过期项
    latest_idx = DATA_DIR / "latest" / "index.json"
    prev = []
    if latest_idx.exists():
        try:
            prev = json.loads(latest_idx.read_text(encoding="utf-8"))
        except Exception:
            prev = []
    nowt = now_utc()
    alive = [it for it in items if not is_expired(it, rules, nowt)]

    prev_map = {i["id"]: i for i in prev}
    for pid, pit in prev_map.items():
        if pid not in {i["id"] for i in alive}:
            if not is_expired(pit, rules, nowt):
                alive.append(pit)

    alive.sort(key=lambda x: x.get("published",""), reverse=True)

    latest_dir = DATA_DIR / "latest"
    archive_dir = DATA_DIR / "archive" / nowt.strftime("%Y-%m")
    latest_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)

    write_json(latest_idx, alive)
    with (archive_dir / "snapshot.ndjson").open("a", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

    PUB_DIR.mkdir(parents=True, exist_ok=True)
    (PUB_DIR / "index.html").write_text(render_index_html(alive), encoding="utf-8")
    (PUB_DIR / "feed.json").write_text(json.dumps(alive[:200], ensure_ascii=False, indent=2), encoding="utf-8")
    (PUB_DIR / "feed.xml").write_text(render_atom_feed(alive), encoding="utf-8")
    (PUB_DIR / "status.html").write_text(render_status_html(state), encoding="utf-8")

    write_json(state_path, state)
    summary = {
        "time": start.isoformat(),
        "run_group": run_group,
        "fetched_sources": fetched,
        "skipped_sources": skipped,
        "total_sources": len(sources),
        "alive_items": len(alive),
        "new_items_this_run": len(items),
    }
    write_json(LOG_DIR / "summary.json", summary)
    log(f"SUMMARY {json.dumps(summary, ensure_ascii=False)}")

if __name__ == "__main__":
    main()
