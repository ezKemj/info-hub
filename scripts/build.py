
import os, re, json, time, hashlib, datetime as dt
import feedparser
from pathlib import Path
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "sources"
DATA = ROOT / "data"
PUB  = ROOT / "public"
RULE = ROOT / "rules"

WHITELIST = {w.strip() for w in (RULE/"whitelist.txt").read_text(encoding="utf-8").splitlines() if w.strip()}
BLACKLIST = {w.strip() for w in (RULE/"blacklist.txt").read_text(encoding="utf-8").splitlines() if w.strip()}
PERSIST_DOMAINS = {w.strip() for w in (RULE/"persistent_domains.txt").read_text(encoding="utf-8").splitlines() if w.strip()}

def load_sources():
    urls = []
    # very simple OPML/line parser (assumes one url per line if not opml)
    for line in (SRC/"rsshub.txt").read_text(encoding="utf-8").splitlines():
        line=line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    # OPML minimal parse
    opml = (SRC/"official.opml").read_text(encoding="utf-8", errors="ignore")
    urls += re.findall(r'xmlUrl="([^"]+)"', opml)
    return sorted(set(urls))

def html_to_text(s):
    return BeautifulSoup(s or "", "lxml").get_text(" ", strip=True)

def norm_item(src, e):
    title = (getattr(e, "title", "") or "").strip()
    link  = (getattr(e, "link" , "") or "").strip()
    summ  = html_to_text(getattr(e, "summary", "") or getattr(e, "description",""))
    pub   = getattr(e, "published", "") or getattr(e, "updated","") or ""
    srcdom = re.sub(r"^https?://","", src).split("/")[0]
    raw = {
        "source": src, "source_domain": srcdom, "title": title, "link": link,
        "summary": summ, "published": pub
    }
    sig = hashlib.sha1((title + "|" + link + "|" + srcdom).encode("utf-8")).hexdigest()
    raw["id"] = sig
    return raw

def is_white(text):
    return any(k in text for k in WHITELIST) if WHITELIST else True

def is_black(text):
    return any(k in text for k in BLACKLIST) if BLACKLIST else False

def is_persistent(item):
    return item["source_domain"] in PERSIST_DOMAINS

def is_expired(item, now):
    if is_persistent(item):
        return False
    # classify by keywords for TTL
    txt = (item["title"] + " " + item["summary"])
    if any(k in txt for k in ["预警","停诊","延误","封闭","中断","限流","通告","调整","变更"]):
        ttl = dt.timedelta(hours=72)
    else:
        ttl = dt.timedelta(days=14)
    # published parse (fallback to now-0)
    try:
        pub = feedparser.parse("data:,x")._parse_date(item["published"])  # use feedparser's parser
        pub_dt = dt.datetime(*pub[:6], tzinfo=dt.timezone.utc) if pub else now
    except Exception:
        pub_dt = now
    return (now - pub_dt) > ttl

def main():
    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    urls = load_sources()
    latest_dir = DATA / "latest"
    archive_dir = DATA / "archive" / now.strftime("%Y-%m")
    latest_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)

    # load previous state
    prev = {}
    if (latest_dir/"index.json").exists():
        prev = {i["id"]: i for i in json.loads((latest_dir/"index.json").read_text("utf-8"))}

    items = []
    for u in urls:
        feed = feedparser.parse(u)
        for e in feed.entries:
            it = norm_item(u, e)
            text = (it["title"] + " " + it["summary"])
            if not is_white(text) or is_black(text):
                continue
            items.append(it)

    # de-dup
    uniq = {}
    for it in items:
        uniq[it["id"]] = it
    items = list(uniq.values())

    # expire filter
    alive, expired = [], []
    for it in items:
        if is_expired(it, now):
            expired.append(it)
        else:
            alive.append(it)

    # merge with prev (keep previously alive unless expired now)
    for pid, pit in prev.items():
        if pid not in uniq and not is_expired(pit, now):
            alive.append(pit)

    # sort by published desc (fallback to id)
    alive.sort(key=lambda x: (x.get("published",""), x["id"]), reverse=True)

    # write outputs
    (latest_dir/"index.json").write_text(json.dumps(alive, ensure_ascii=False, indent=2), "utf-8")
    with (archive_dir/"snapshot.ndjson").open("a", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

    # very small html & json feed
    PUB.mkdir(parents=True, exist_ok=True)
    # index.html (ul list)
    lis = "\n".join(
        f'<li><a href="{i["link"]}" target="_blank">{i["title"]}</a> '
        f'<small>({i["source_domain"]})</small><br><em>{i.get("summary","")[:160]}</em></li>'
        for i in alive[:200]
    )
    html = f"""<!doctype html><meta charset="utf-8"><title>InfoHub</title>
<style>body{{font:14px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;max-width:860px;margin:24px auto;padding:0 12px}}li{{margin:10px 0}}</style>
<h1>InfoHub（权威源聚合）</h1>
<ul>{lis}</ul>"""
    (PUB/"index.html").write_text(html, "utf-8")
    (PUB/"feed.json").write_text(json.dumps(alive[:200], ensure_ascii=False, indent=2), "utf-8")

if __name__ == "__main__":
    main()
