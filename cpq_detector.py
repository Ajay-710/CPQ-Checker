#!/usr/bin/env python3
"""Production-grade CPQ (Configure, Price, Quote) detection engine.

Multi-signal detection:
  1. HTML content fingerprinting (visible text, meta tags, inline scripts)
  2. External script source analysis
  3. HTTP header & cookie fingerprinting
  4. Subdomain probing (always-on)
  5. Deep link crawling (configurable)
  6. iframe/embed source analysis
"""
import argparse, asyncio, csv, json, os, random, re, signal, sys, time
from urllib.parse import urljoin, urlparse, urldefrag
import aiohttp, tldextract
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

ua = UserAgent()

CHECKPOINT_FILE = "cpq_checkpoint.json"
RESULTS_FILE = "cpq_results.csv"
ERRORS_FILE = "cpq_errors.csv"
MAX_HTML_BYTES = 2_500_000
MAX_ASSET_BYTES = 500_000
MAX_SCRIPTS = 8
MAX_LINKS = 20
MAX_CANDIDATE_PATHS = 14
SAVE_EVERY = 100
STOP = False

# A stable browser signature is more reliable than a rotating one.  Some WAFs
# reject the inconsistent headers produced by random user-agent generators.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Subdomain wordlist — always probed for every domain
# ---------------------------------------------------------------------------
CPQ_SUBDOMAINS = [
    "quote", "cpq", "configure", "configurator",
    "partners", "partner", "portal",
    "shop", "store", "b2b", "commerce",
    "catalog", "order", "orders", "pricing",
    "dealer", "dealers", "distributor",
    "selfservice", "myaccount", "eshop",
]

# Public routes frequently used for a configurator.  They are deliberately
# small and only checked on the target host; this catches tools that are not
# linked from the marketing homepage.
CPQ_PATHS = [
    "/quote", "/quotes", "/request-a-quote", "/request-quote",
    "/configurator", "/configure", "/product-configurator", "/builder",
    "/pricing", "/dealer-portal", "/partner-portal", "/b2b", "/shop",
    "/catalog", "/rfq",
]

# ---------------------------------------------------------------------------
# FINGERPRINTS — 50+ CPQ and B2B commerce vendors
# ---------------------------------------------------------------------------
FINGERPRINTS = {
# --- Tier 1: Major CPQ Platforms ---
"Salesforce CPQ": {
    "strong": [r"\bSBQQ__", r"\bSBQQ\b", r"/apex/SBQQ", r"SBQQ\.Quote", r"window\.SBQQ", r"sf-cpq", r"cpq\.salesforce", r"revvy\.com"],
    "medium": [r"salesforce.*cpq", r"quote line editor", r"steelbrick", r"salesforce.*quote"],
    "domains": ["salesforce.com", "force.com", "visualforce.com", "steelbrick.com"],
    "cookies": ["BIGipServerSFDC", "sfdc-stream", "SFDC_CPQ"],
    "headers": [],
},
"Oracle CPQ": {
    "strong": [r"/cpq/rest/", r"/bmi/", r"oraclecpq", r"cpq\.oraclecloud", r"bigmachines", r"bm\.oracle", r"BIGipServer[a-zA-Z0-9_]*CPQ"],
    "medium": [r"oracle.*cpq", r"oracle commerce"],
    "domains": ["oracle.com", "oraclecloud.com", "bigmachines.com"],
    "cookies": ["ORA_CPQ", "BIGMACHINES"],
    "headers": ["x-oracle-cpq"],
},
"SAP CPQ": {
    "strong": [r"sap.*cpq", r"calliduscloud.*cpq", r"calliduscloud", r"sap\.hybris", r"spartacus", r"cx\.sap", r"sap commerce"],
    "medium": [r"configure.*price.*quote.*sap", r"sap\.com/products/cpq"],
    "domains": ["sap.com", "calliduscloud.com", "hybris.com"],
    "cookies": ["SAP_SESSIONID", "sap-contextid"],
    "headers": ["sap-server"],
},
"Conga CPQ": {
    "strong": [r"conga.*cpq", r"apttus.*cpq", r"\bApttus__", r"\bApttus\b", r"conga-cpq"],
    "medium": [r"conga quote", r"conga.*configure"],
    "domains": ["conga.com", "apttus.com"],
    "cookies": ["_apttus_session"],
    "headers": [],
},
"Epicor CPQ": {
    "strong": [r"epicor.*cpq", r"epicor configurator", r"kbmax", r"epicor\.com/cpq"],
    "medium": [r"epicor.*quote", r"epicor.*configure"],
    "domains": ["epicor.com", "kbmax.com"],
    "cookies": [],
    "headers": [],
},
"ConnectWise CPQ": {
    "strong": [r"connectwise.*cpq", r"connectwise.*sell", r"quote\.connectwise", r"sell\.connectwise"],
    "medium": [r"connectwise sell"],
    "domains": ["connectwise.com"],
    "cookies": [],
    "headers": [],
},
"PROS CPQ": {
    "strong": [r"pros.*cpq", r"pros smart cpq", r"pros\.com/cpq", r"proscloud"],
    "medium": [r"pros quote", r"pros.*pricing"],
    "domains": ["pros.com"],
    "cookies": [],
    "headers": [],
},
"DealHub CPQ": {
    "strong": [r"dealhub.*cpq", r"dealhub\.io", r"dealhub.*configure"],
    "medium": [r"dealhub quote", r"dealhub.*proposal"],
    "domains": ["dealhub.io"],
    "cookies": [],
    "headers": [],
},

# --- Tier 2: Mid-market CPQ ---
"Infor CPQ": {
    # Word boundaries prevent "information ... quote" from being classified
    # as the vendor Infor on ordinary marketing pages.
    "strong": [r"\binfor\b.*cpq", r"\binfor\b configure price quote", r"\binfor\b configurator", r"infor\.com/cpq"],
    "medium": [r"\binfor\b.*quote"],
    "domains": ["infor.com"],
    "cookies": [],
    "headers": [],
},
"Model N CPQ": {
    "strong": [r"modeln.*cpq", r"model n.*configure.*price"],
    "medium": [r"model n.*cpq"],
    "domains": ["modeln.com"],
    "cookies": [],
    "headers": [],
},
"Cincom CPQ": {
    "strong": [r"cincom.*cpq", r"cincom eloquence", r"cincom configure"],
    "medium": [r"cincom.*quote"],
    "domains": ["cincom.com"],
    "cookies": [],
    "headers": [],
},
"Experlogix CPQ": {
    "strong": [r"experlogix.*cpq", r"experlogix.*configuration", r"cdn\.experlogix\.com"],
    "medium": [r"experlogix.*quote"],
    "domains": ["experlogix.com"],
    "cookies": [],
    "headers": [],
},
"Tacton CPQ": {
    "strong": [r"tacton.*cpq", r"tacton configurator", r"tacton\.com/cpq"],
    "medium": [r"tacton.*quote"],
    "domains": ["tacton.com"],
    "cookies": [],
    "headers": [],
},
"Zuora CPQ": {
    "strong": [r"zuora.*cpq", r"zuora quotes", r"zuora\.com/cpq"],
    "medium": [r"zuora quote"],
    "domains": ["zuora.com"],
    "cookies": [],
    "headers": [],
},
"IBM Sterling CPQ": {
    "strong": [r"ibm.*sterling.*cpq", r"sterling.*configure.*price.*quote"],
    "medium": [r"ibm sterling.*cpq"],
    "domains": ["ibm.com"],
    "cookies": [],
    "headers": [],
},
"FPX CPQ": {
    "strong": [r"\bfpx cpq\b", r"fpx.*configure.*price"],
    "medium": [r"\bfpx\b.*quote"],
    "domains": ["fpx.com"],
    "cookies": [],
    "headers": [],
},
"ServiceNow CPQ": {
    "strong": [r"servicenow.*cpq", r"configure.*price.*quote.*servicenow"],
    "medium": [r"servicenow.*quote"],
    "domains": ["servicenow.com"],
    "cookies": [],
    "headers": [],
},

# --- Tier 3: Niche / Emerging CPQ ---
"Logik.io": {
    "strong": [r"logik\.io", r"logikio", r"logik.*cpq"],
    "medium": [],
    "domains": ["logik.io"],
    "cookies": [],
    "headers": [],
},
"Vlocity CPQ": {
    "strong": [r"vlocity.*cpq", r"vlocity configurator", r"omnistudio"],
    "medium": [r"vlocity quote"],
    "domains": ["vlocity.com"],
    "cookies": [],
    "headers": [],
},
"ThreeKit": {
    "strong": [r"threekit.*cpq", r"threekit 3d configurator", r"threekit\.com"],
    "medium": [r"threekit"],
    "domains": ["threekit.com"],
    "cookies": [],
    "headers": [],
},
"Expedite Commerce": {
    "strong": [r"expedite.*commerce", r"expeditecommerce"],
    "medium": [],
    "domains": ["expeditecommerce.com"],
    "cookies": [],
    "headers": [],
},
"Vendavo": {
    "strong": [r"vendavo.*cpq", r"vendavo.*pricing", r"vendavo\.com"],
    "medium": [r"vendavo"],
    "domains": ["vendavo.com"],
    "cookies": [],
    "headers": [],
},
"CloudSense": {
    "strong": [r"cloudsense.*cpq", r"cloudsense\.com"],
    "medium": [r"cloudsense"],
    "domains": ["cloudsense.com"],
    "cookies": [],
    "headers": [],
},
"PandaDoc": {
    "strong": [r"pandadoc.*cpq", r"pandadoc.*quote", r"pandadoc\.com"],
    "medium": [r"pandadoc"],
    "domains": ["pandadoc.com"],
    "cookies": [],
    "headers": [],
},
"Proposify": {
    "strong": [r"proposify.*cpq", r"proposify\.com"],
    "medium": [r"proposify"],
    "domains": ["proposify.com"],
    "cookies": [],
    "headers": [],
},
"Netsuite CPQ": {
    "strong": [r"netsuite.*cpq", r"netsuite.*configure.*price"],
    "medium": [r"netsuite.*quote"],
    "domains": ["netsuite.com"],
    "cookies": [],
    "headers": [],
},
"HubSpot Quotes": {
    "strong": [r"hubspot.*cpq", r"hubspot.*quotes"],
    "medium": [r"hs-quotes"],
    "domains": ["hubspot.com"],
    "cookies": [],
    "headers": [],
},
"Corevist": {
    "strong": [r"corevist.*cpq", r"corevist\.com"],
    "medium": [r"corevist"],
    "domains": ["corevist.com"],
    "cookies": [],
    "headers": [],
},
"Magento B2B": {
    "strong": [r"magento.*b2b", r"magento.*cpq"],
    "medium": [r"magento.*commerce.*b2b", r"adobe.*commerce.*b2b"],
    "domains": ["magento.com"],
    "cookies": ["PHPSESSID"],  # Will be combined with other magento signals
    "headers": ["x-magento"],
},
"Shopify Plus B2B": {
    "strong": [r"shopify.*b2b", r"shopify.*wholesale"],
    "medium": [r"shopify plus.*b2b"],
    "domains": ["shopify.com", "myshopify.com"],
    "cookies": ["_shopify_s"],
    "headers": [],
},
"CloudBlue": {
    "strong": [r"cloudblue.*cpq", r"cloudblue\.com"],
    "medium": [r"cloudblue"],
    "domains": ["cloudblue.com"],
    "cookies": [],
    "headers": [],
},
"Technicon CPQ": {
    "strong": [r"technicon.*cpq", r"technicon.*configur"],
    "medium": [r"technicon.*quote"],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Powertrak CPQ": {
    "strong": [r"powertrak.*cpq", r"powertrak.*configur"],
    "medium": [r"powertrak.*quote"],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"e-Con CPQ": {
    "strong": [r"e-con.*cpq", r"e-con solutions.*cpq", r"e-con.*configurator"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Zilliant CPQ": {
    "strong": [r"zilliant.*cpq"],
    "medium": [r"zilliant.*quote"],
    "domains": ["zilliant.com"],
    "cookies": [],
    "headers": [],
},
"Mobileforce CPQ": {
    "strong": [r"mobileforce.*cpq", r"mobileforce.*quote"],
    "medium": [],
    "domains": ["mobileforcesoftware.com"],
    "cookies": [],
    "headers": [],
},
"Lino 3D CPQ": {
    "strong": [r"lino.*cpq", r"lino 3d.*configur"],
    "medium": [r"lino.*configurator"],
    "domains": ["lino.de"],
    "cookies": [],
    "headers": [],
},
"servicePath CPQ+": {
    "strong": [r"servicepath.*cpq", r"servicepath.*quote"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Solidify CPQ": {
    "strong": [r"solidify.*cpq", r"solidify.*quote"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Veloce CPQ": {
    "strong": [r"veloce.*cpq", r"veloce configurator"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"BigTime Services CPQ": {
    "strong": [r"bigtime.*cpq", r"bigtime services.*quote"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Right Information CPQ": {
    "strong": [r"right information.*cpq", r"rightinformation.*cpq"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Sculptor CPQ": {
    "strong": [r"sculptor.*cpq", r"sculptor configurator"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Ventas CPQ": {
    "strong": [r"ventas.*cpq", r"ventas.*sms.*solution"],
    "medium": [],
    "domains": [],
    "cookies": [],
    "headers": [],
},
"Verenia CPQ": {
    "strong": [r"verenia.*cpq", r"verenia\.com"],
    "medium": [],
    "domains": ["verenia.com"],
    "cookies": [],
    "headers": [],
},
"Configure One": {
    "strong": [r"configureone", r"configure one.*cpq"],
    "medium": [],
    "domains": ["configureone.com"],
    "cookies": [],
    "headers": [],
},
"Bit2win CPQ": {
    "strong": [r"bit2win.*cpq", r"bit2win\.com"],
    "medium": [],
    "domains": ["bit2win.com"],
    "cookies": [],
    "headers": [],
},
"Appsmart CPQ": {
    "strong": [r"appsmart.*cpq"],
    "medium": [],
    "domains": ["appsmart.com"],
    "cookies": [],
    "headers": [],
},
"Xait CPQ": {
    "strong": [r"xait.*cpq", r"xaitporter"],
    "medium": [],
    "domains": ["xait.com"],
    "cookies": [],
    "headers": [],
},
}

# ---------------------------------------------------------------------------
# Generic B2B / CPQ keyword patterns for fallback detection
# ---------------------------------------------------------------------------
GENERIC_CPQ_RE = re.compile(
    r"\bcpq\b"
    r"|configure[, ]+price[, ]+quote"
    r"|product\s*configurator"
    r"|dealer\s*portal"
    r"|b2b\s*commerce"
    r"|b2b\s*e[\-\s]*commerce"
    r"|partner\s*portal"
    r"|request\s+a?\s*quote"
    r"|get\s+a?\s*quote"
    r"|build\s+your\s+own"
    r"|custom\s*configurator"
    r"|product\s*builder"
    r"|quote\s*request"
    r"|rfq\s*form"
    r"|request\s*for\s*quotation"
    r"|self[\-\s]*service\s*portal"
    r"|configure\s+your"
    r"|pricing\s*calculator"
    r"|instant\s*quote"
    r"|online\s*quoting"
    r"|quote\s*generator",
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def stop_handler(*_):
    global STOP; STOP = True; print("\nStopping safely...")

signal.signal(signal.SIGINT, stop_handler)

def norm(v):
    if not v: return None
    v = str(v).strip().replace("\ufeff", "")
    if "://" not in v: v = "https://" + v
    h = urlparse(v).netloc.lower().split("@")[-1].split(":")[0].strip(".")
    return h if h and "." in h else None

def reg(h):
    e = tldextract.extract(h)
    return ".".join(x for x in (e.domain, e.suffix) if x) or h

def conf(s):
    return "CONFIRMED" if s >= 90 else "LIKELY" if s >= 60 else "POSSIBLE" if s >= 15 else "NOT_DETECTED"

def snippet(t, a, b):
    return re.sub(r"\s+", " ", t[max(0, a - 120):min(len(t), b + 180)]).strip()

def user_agent():
    """Return a usable UA even when fake-useragent has no cached data."""
    try:
        return ua.random or DEFAULT_USER_AGENT
    except Exception:
        return DEFAULT_USER_AGENT

def page_corpus(html, headers="", cookies="", final_url=""):
    """Include visible content *and* route/attribute metadata in detection.

    SPAs often expose their CPQ vendor only in data attributes, preload links,
    JSON-LD, or JavaScript URLs.  Restricting generic language to visible text
    was the largest source of missed detections.
    """
    soup = BeautifulSoup(html, "html.parser")
    raw_tags = str(soup.find_all(["script", "meta", "link", "form", "iframe", "a"]))
    for tag in soup(["script", "style", "noscript"]):
        tag.extract()
    visible = soup.get_text(separator=" ", strip=True)
    return soup, visible, "\n".join([visible, raw_tags, headers, cookies, final_url])

# ---------------------------------------------------------------------------
# Core detection: regex fingerprints against a text corpus
# ---------------------------------------------------------------------------
def detect(text, label):
    low = text.lower()
    out = []
    for vendor, fp in FINGERPRINTS.items():
        score = 0
        ev = []
        for patterns, pts, name in ((fp["strong"], 50, "STRONG"), (fp["medium"], 20, "MEDIUM")):
            for p in patterns:
                try:
                    m = re.search(p, low, re.I)
                except re.error:
                    m = None
                if m:
                    score += pts
                    ev.append(f"[{label}] {name}: " + snippet(text, m.start(), m.end()))
        for d in fp["domains"]:
            if d.lower() in low:
                score += 35
                ev.append(f"[{label}] VENDOR_DOMAIN: {d}")
        score = min(100, score)
        if score >= 20:
            out.append((vendor, score, ev[:6]))
    return out

# ---------------------------------------------------------------------------
# HTTP header & cookie fingerprinting
# ---------------------------------------------------------------------------
def detect_headers_cookies(headers_str, cookies_str):
    """Detect CPQ from HTTP response headers and cookies."""
    out = []
    combined = (headers_str + "\n" + cookies_str).lower()
    for vendor, fp in FINGERPRINTS.items():
        score = 0
        ev = []
        for cookie_pattern in fp.get("cookies", []):
            if cookie_pattern.lower() in combined:
                score += 30
                ev.append(f"[header/cookie] COOKIE: {cookie_pattern}")
        for header_pattern in fp.get("headers", []):
            if header_pattern.lower() in combined:
                score += 30
                ev.append(f"[header/cookie] HEADER: {header_pattern}")
        if score > 0:
            out.append((vendor, min(100, score), ev[:4]))
    return out

# ---------------------------------------------------------------------------
# Network fetch
# ---------------------------------------------------------------------------
async def fetch(session, url, timeout, max_bytes, verify_ssl=True):
    headers = {
        'User-Agent': user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        # Do not advertise Brotli unless the optional decoder is guaranteed to
        # be installed. A response encoded as `br` otherwise fails before its
        # HTML can be inspected (aiohttp ClientResponseError 400).
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1'
    }
    try:
        async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=timeout), headers=headers, ssl=verify_ssl) as r:
            chunks = []
            n = 0
            async for c in r.content.iter_chunked(65536):
                chunks.append(c)
                n += len(c)
                if n >= max_bytes:
                    break
            raw = b"".join(chunks)
            try:
                body = raw.decode(r.charset or "utf-8", errors="ignore")
            except LookupError:
                body = raw.decode("utf-8", errors="ignore")
            headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            cookies_str = "\n".join(f"{k}: {v.value}" for k, v in r.cookies.items())
            return True, str(r.url), r.status, body, headers_str, cookies_str, ""
    except Exception as e:
        return False, url, "", "", "", "", "%s: %s" % (type(e).__name__, str(e)[:250])

# ---------------------------------------------------------------------------
# Extract script sources
# ---------------------------------------------------------------------------
def extract_scripts(base, soup):
    return [urljoin(base, x.get('src')) for x in soup.find_all('script') if x.get('src') and urljoin(base, x.get('src')).startswith(("http://", "https://"))][:MAX_SCRIPTS]

# ---------------------------------------------------------------------------
# Extract iframes and embeds
# ---------------------------------------------------------------------------
def extract_embeds(base, soup):
    out = []
    for tag in soup.find_all(['iframe', 'embed', 'object']):
        src = tag.get('src') or tag.get('data') or ''
        if src:
            full = urljoin(base, src)
            if full.startswith(("http://", "https://")):
                out.append(full)
    return out[:10]

# ---------------------------------------------------------------------------
# Extract deep crawl links (URL + visible link text matching)
# ---------------------------------------------------------------------------
def extract_links(base, soup):
    kws = (
        "configur", "quote", "pricing", "price", "build", "custom",
        "product", "rfq", "commerce", "partner", "dealer", "portal",
        "catalog", "shop", "store", "b2b", "order", "wholesale",
    )
    host = reg(urlparse(base).netloc)
    out = []
    seen = set()
    for a in soup.find_all('a', href=True):
        u = urldefrag(urljoin(base, a['href']))[0]
        txt = " ".join((a.get_text(" "), a.get("aria-label", ""), a.get("title", ""))).lower()
        if u.startswith(("http://", "https://")) and reg(urlparse(u).netloc) == host and u not in seen:
            if any(k in u.lower() for k in kws) or any(k in txt for k in kws):
                seen.add(u)
                out.append(u)
    return out[:MAX_LINKS]

def candidate_paths(base):
    """Return a bounded set of high-value same-host routes to inspect."""
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    return [root + path for path in CPQ_PATHS[:MAX_CANDIDATE_PATHS]]

def generic_evidence(corpus, label):
    m = GENERIC_CPQ_RE.search(corpus)
    return f"[{label}] GENERIC: {snippet(corpus, m.start(), m.end())}" if m else ""

def target_vendor(domain):
    """Identify a CPQ vendor when the submitted host is its own domain.

    This is an authoritative input-level signal and also gives a useful answer
    when the vendor's website blocks automated page retrieval.
    """
    host = domain.lower().strip(".")
    for vendor, fp in FINGERPRINTS.items():
        for vendor_domain in fp["domains"]:
            vendor_domain = vendor_domain.lower()
            if host == vendor_domain or host.endswith("." + vendor_domain):
                return vendor
    return None

# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------
async def scan(session, domain, args):
    print(f"[SCAN V2] Starting scan for {domain}, deep_scan={args.deep_scan}, scan_scripts={args.scan_scripts}")
    start = time.perf_counter()
    result = {
        "domain": domain, "final_url": "", "http_status": "",
        "cpq_detected": "NO", "cpq_vendor": "", "confidence": "NOT_DETECTED",
        "score": 0, "detection_method": "", "evidence": "",
        "scan_time_seconds": 0, "error": ""
    }

    # A vendor's own domain is a deterministic identification signal.  Check
    # it before network work so blocked vendor sites are never misreported as
    # NOT_DETECTED.
    known_vendor = target_vendor(domain)
    if known_vendor:
        result.update(
            cpq_detected="YES", cpq_vendor=known_vendor,
            confidence="CONFIRMED", score=100,
            detection_method="target-domain",
            evidence=f"[target-domain] Submitted host matches the official {known_vendor} domain"
        )
        result["scan_time_seconds"] = round(time.perf_counter() - start, 2)
        return result

    first = None
    x = None
    # Prefer modern HTTPS endpoints; most sites that do not serve the apex
    # host serve `www`. This keeps a failed host from consuming the full scan
    # budget before content inspection begins.
    urls_to_try = [("https://" + domain, True)]
    for u, verify in urls_to_try:
        # Do not spend a full request timeout on each HTTPS/HTTP fallback.
        x = await fetch(session, u, min(args.timeout, 7), MAX_HTML_BYTES, verify_ssl=verify)
        if x[0]:
            first = x
            break

    # Some sites expose the public application only on www even though the
    # apex host accepts DNS but never completes HTTP/TLS.
    if not first and not domain.startswith("www."):
        x = await fetch(session, "https://www." + domain, min(args.timeout, 6), MAX_HTML_BYTES)
        if x[0]:
            first = x

    if not first:
        result.update(
            cpq_detected="UNKNOWN", confidence="SCAN_FAILED",
            evidence="No HTTP response was received; this is not a negative CPQ finding.",
            error=x[6] if x else "Connection failed"
        )
        result["scan_time_seconds"] = round(time.perf_counter() - start, 2)
        return result

    _, url, status, html, headers, cookies, _ = first
    result.update(final_url=url, http_status=status)

    # A WAF, login wall, or rate limit prevents a defensible negative result.
    # Preserve the HTTP status and make the uncertainty explicit.
    if status in (401, 403, 429):
        result.update(
            cpq_detected="UNKNOWN", confidence="ACCESS_RESTRICTED",
            evidence=f"HTTP {status} prevented public-content inspection; this is not a negative CPQ finding."
        )
        result["scan_time_seconds"] = round(time.perf_counter() - start, 2)
        return result

    # -----------------------------------------------------------------------
    # Signal 1: Parse homepage HTML
    # -----------------------------------------------------------------------
    soup = BeautifulSoup(html, 'html.parser')

    soup, visible_text, search_corpus = page_corpus(html, headers, cookies, url)

    hits = detect(search_corpus, "homepage")
    generic_signals = []
    homepage_generic = generic_evidence(search_corpus, "homepage")
    if homepage_generic:
        generic_signals.append(homepage_generic)
    methods = ["homepage"]

    # -----------------------------------------------------------------------
    # Signal 2: HTTP header & cookie fingerprinting
    # -----------------------------------------------------------------------
    header_hits = detect_headers_cookies(headers, cookies)
    hits += header_hits
    if header_hits:
        methods.append("headers")

    # -----------------------------------------------------------------------
    # Signal 3: iframe/embed source analysis
    # -----------------------------------------------------------------------
    # Re-parse for embeds since we extracted script/style above
    embed_soup = BeautifulSoup(html, 'html.parser')
    for embed_url in extract_embeds(url, embed_soup):
        embed_hits = detect(embed_url, "embed")
        hits += embed_hits
        if embed_hits:
            methods.append("embeds")
            break  # Only need one embed match

    # -----------------------------------------------------------------------
    # Signal 4: External script scanning
    # -----------------------------------------------------------------------
    if args.scan_scripts:
        script_soup = BeautifulSoup(html, 'html.parser')
        script_urls = extract_scripts(url, script_soup)
        for su in script_urls:
            # First check if the script URL itself contains vendor domains
            url_hits = detect(su, "script_url")
            hits += url_hits
        # Asset requests are independent; sequential fetching made one slow CDN
        # hold up the entire target scan.
        script_fetches = await asyncio.gather(*[
            fetch(session, su, min(args.timeout, 5), MAX_ASSET_BYTES) for su in script_urls
        ])
        for x in script_fetches:
            if x[0]:
                hits += detect(x[3] + "\n" + x[1], "script")
        methods.append("scripts")

    # -----------------------------------------------------------------------
    # Signal 5: probe common CPQ subdomains in deep mode.  Doing this for every
    # row in a large CSV creates hundreds of slow DNS/TLS attempts and harms
    # both throughput and accuracy through self-induced timeouts.
    # -----------------------------------------------------------------------
    async def check_subdomain(sub):
        sub_url = "https://" + sub + "." + domain
        # Most nonexistent CPQ subdomains fail fast.  A short cap prevents a
        # handful of filtered DNS/HTTPS hosts from holding the UI hostage.
        x = await fetch(session, sub_url, min(args.timeout, 6), MAX_HTML_BYTES)
        if x[0]:
            _, ptext, corpus = page_corpus(x[3], x[4], "", x[1])
            res = detect(corpus, f"subdomain:{sub}")
            return res, generic_evidence(corpus, f"subdomain:{sub}")
        return [], ""

    if getattr(args, "scan_subdomains", False):
        sub_results = await asyncio.gather(*[check_subdomain(sub) for sub in CPQ_SUBDOMAINS])
        for s_hits, s_gen in sub_results:
            hits += s_hits
            if s_gen:
                generic_signals.append(s_gen)
        methods.append("subdomains")

    # Signal 6: probe a small set of common configurator routes.  Run in
    # parallel and only retain successful CPQ evidence, so normal 404s do not
    # affect the result.
    if getattr(args, "scan_paths", True):
        async def check_path(path_url):
            x = await fetch(session, path_url, min(args.timeout, 7), MAX_HTML_BYTES)
            if x[0] and 200 <= x[2] < 400:
                _, _, corpus = page_corpus(x[3], x[4], x[5], x[1])
                return detect(corpus, "known_path"), generic_evidence(corpus, "known_path")
            return [], ""
        path_results = await asyncio.gather(*[check_path(p) for p in candidate_paths(url)])
        for p_hits, p_generic in path_results:
            hits += p_hits
            if p_generic:
                generic_signals.append(p_generic)
        methods.append("paths")

    # -----------------------------------------------------------------------
    # Signal 7: Deep link crawling (optional, but more thorough)
    # -----------------------------------------------------------------------
    if args.deep_scan:
        deep_soup = BeautifulSoup(html, 'html.parser')
        for lu in extract_links(url, deep_soup):
            if STOP:
                break
            x = await fetch(session, lu, args.timeout, MAX_HTML_BYTES)
            if x[0]:
                _, _, corpus = page_corpus(x[3], x[4], x[5], x[1])
                hits += detect(corpus, "deep")
                deep_generic = generic_evidence(corpus, "deep")
                if deep_generic:
                    generic_signals.append(deep_generic)
        methods.append("deep")

    # -----------------------------------------------------------------------
    # Merge results and determine confidence
    # -----------------------------------------------------------------------
    merged = {}
    for v, s, e in hits:
        if v not in merged:
            merged[v] = [0, []]
        merged[v][0] = min(100, merged[v][0] + s)
        merged[v][1] += e

    if merged:
        v = max(merged, key=lambda z: merged[z][0])
        s = merged[v][0]
        result.update(
            cpq_vendor=v,
            confidence=conf(s),
            score=s,
            evidence=" | ".join(list(dict.fromkeys(merged[v][1]))[:8])
        )
    elif generic_signals:
        result.update(
            cpq_detected="YES",
            confidence="POSSIBLE",
            score=15,
            cpq_vendor="Generic CPQ / B2B commerce",
            evidence=" | ".join(list(dict.fromkeys(generic_signals))[:4])
        )

    result["cpq_detected"] = "YES" if result["confidence"] != "NOT_DETECTED" else "NO"
    result["detection_method"] = ",".join(methods)
    result["scan_time_seconds"] = round(time.perf_counter() - start, 2)
    return result

# ---------------------------------------------------------------------------
# CSV / CLI support
# ---------------------------------------------------------------------------
FIELDS = ["domain", "final_url", "http_status", "cpq_detected", "cpq_vendor", "confidence", "score", "detection_method", "evidence", "scan_time_seconds", "error"]

def read_domains(path, column):
    with open(path, encoding="utf-8-sig", newline="") as f:
        sample = f.read(8192)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        r = csv.DictReader(f, dialect=dialect)
        heads = r.fieldnames
        if not heads:
            raise ValueError("CSV has no header")
        lookup = {h.lower().strip(): h for h in heads}
        col = column or next((lookup[x] for x in ("domain", "domains", "website", "website_url", "url", "company_domain", "company website") if x in lookup), heads[0])
        seen = set()
        out = []
        for row in r:
            d = norm(row.get(col))
            if d and d not in seen:
                seen.add(d)
                out.append(d)
    return out, col

def load_done():
    try:
        with open(CHECKPOINT_FILE, encoding="utf-8") as f:
            return set(json.load(f).get("completed", []))
    except Exception:
        return set()

def save_done(done):
    with open(CHECKPOINT_FILE + ".tmp", "w", encoding="utf-8") as f:
        json.dump({"completed": sorted(done)}, f)
    os.replace(CHECKPOINT_FILE + ".tmp", CHECKPOINT_FILE)

def write_rows(rows):
    if not rows:
        return
    exists = os.path.exists(RESULTS_FILE)
    with open(RESULTS_FILE, "a", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if not exists:
            w.writeheader()
        w.writerows(rows)
    errs = [x for x in rows if x["error"]]
    if errs:
        exists = os.path.exists(ERRORS_FILE)
        with open(ERRORS_FILE, "a", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["domain", "final_url", "http_status", "error"])
            if not exists:
                w.writeheader()
            for x in errs:
                w.writerow({k: x[k] for k in ["domain", "final_url", "http_status", "error"]})

async def run(args):
    domains, col = read_domains(args.input, args.column)
    done = load_done() if args.resume else set()
    pending = [d for d in domains if d not in done]
    print(f"Domain column: {col}\nUnique domains: {len(domains):,}\nRemaining: {len(pending):,}")
    q = asyncio.Queue()
    for d in pending:
        q.put_nowait(d)
    rows = []
    lock = asyncio.Lock()
    stats = {"n": 0, "confirmed": 0, "likely": 0, "possible": 0}
    start_time = time.perf_counter()
    connector = aiohttp.TCPConnector(limit=max(args.workers * 2, 20), limit_per_host=3, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker():
            while not STOP:
                try:
                    d = q.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    x = await scan(session, d, args)
                except Exception as e:
                    x = {"domain": d, "final_url": "", "http_status": "", "cpq_detected": "NO", "cpq_vendor": "", "confidence": "NOT_DETECTED", "score": 0, "detection_method": "", "evidence": "", "scan_time_seconds": 0, "error": f"{type(e).__name__}: {e}"}
                async with lock:
                    rows.append(x)
                    done.add(d)
                    stats["n"] += 1
                    if x["confidence"] == "CONFIRMED":
                        stats["confirmed"] += 1
                    elif x["confidence"] == "LIKELY":
                        stats["likely"] += 1
                    elif x["confidence"] == "POSSIBLE":
                        stats["possible"] += 1
                    if len(rows) >= SAVE_EVERY:
                        batch = rows[:]
                        rows.clear()
                        write_rows(batch)
                        save_done(done)
                    if stats["n"] % 25 == 0:
                        rate = stats["n"] / max(time.perf_counter() - start_time, 0.01)
                        print(f"\rProcessed {stats['n']:,}/{len(pending):,} | {rate:.2f}/sec | Confirmed {stats['confirmed']:,} | Likely {stats['likely']:,} | Possible {stats['possible']:,}", end="", flush=True)
                q.task_done()
                await asyncio.sleep(random.uniform(0.02, 0.12))
        await asyncio.gather(*[asyncio.create_task(worker()) for _ in range(args.workers)])
    if rows:
        write_rows(rows)
    save_done(done)
    elapsed = time.perf_counter() - start_time
    print(f"\n\nCOMPLETE\nProcessed: {stats['n']:,}\nConfirmed: {stats['confirmed']:,}\nLikely: {stats['likely']:,}\nPossible: {stats['possible']:,}\nElapsed: {elapsed / 60:.1f} min\nResults: {os.path.abspath(RESULTS_FILE)}")
    if STOP:
        print("Stopped safely. Run again with --resume")

def main():
    p = argparse.ArgumentParser(description="Detect public evidence of CPQ technologies")
    p.add_argument("input")
    p.add_argument("--column")
    p.add_argument("--workers", type=int, default=30)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--deep-scan", action="store_true")
    p.add_argument("--no-script-scan", dest="scan_scripts", action="store_false")
    p.add_argument("--no-path-scan", dest="scan_paths", action="store_false",
                   help="skip common quote/configurator routes for a faster scan")
    p.add_argument("--no-subdomain-scan", dest="scan_subdomains", action="store_false",
                   help="skip CPQ subdomain probing for a faster scan")
    p.set_defaults(scan_scripts=True, scan_paths=True, scan_subdomains=True)
    p.add_argument("--resume", action="store_true")
    a = p.parse_args()
    if not os.path.exists(a.input):
        sys.exit("Input file not found: " + a.input)
    if a.workers < 1:
        sys.exit("--workers must be >= 1")
    asyncio.run(run(a))

if __name__ == "__main__":
    main()
