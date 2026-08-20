import asyncio
import csv
import io
import json
import re
import types
from typing import List
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sse_starlette.sse import EventSourceResponse
import aiohttp

# Scanner module is loaded once per worker for predictable production behavior.
import cpq_detector

app = FastAPI(title="CPQ Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_DOMAINS_PER_REQUEST = 250
MAX_SCAN_SECONDS = 40

def _get_scanner():
    """Return the loaded scanner; production workers must not reload mid-scan."""
    return cpq_detector.scan, cpq_detector.norm

async def scan_domain_generator(domains: List[str], deep_scan: bool = False, timeout: int = 20):
    scan_fn, _ = _get_scanner()
    # Standard scans use homepage/assets only. Deep Crawl opts into the costly
    # route and subdomain reconnaissance needed for harder-to-find tools.
    args = types.SimpleNamespace(
        timeout=max(3, min(timeout, 30)), scan_scripts=True, deep_scan=deep_scan,
        scan_paths=deep_scan, scan_subdomains=deep_scan,
    )
    
    # A target scans several assets concurrently. Restricting target-level
    # work avoids exhausting Render sockets during large uploads.
    semaphore = asyncio.Semaphore(2)
    connector = aiohttp.TCPConnector(limit=40, limit_per_host=3, ttl_dns_cache=300)
    # Honor organization-approved standard proxy variables when configured.
    async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
        yield {"event": "progress", "data": json.dumps({"total": len(domains), "completed": 0})}
        
        async def process_domain(d):
            async with semaphore:
                try:
                    result = await asyncio.wait_for(scan_fn(session, d, args), timeout=MAX_SCAN_SECONDS)
                except asyncio.TimeoutError:
                    result = {
                        "domain": d, "final_url": "", "http_status": "",
                        "cpq_detected": "UNKNOWN", "cpq_vendor": "", "confidence": "SCAN_FAILED",
                        "score": 0, "detection_method": "",
                        "scan_time_seconds": MAX_SCAN_SECONDS,
                        "evidence": "No conclusion was reached because the scan exceeded the time limit.",
                        "error": "Scan timed out after 40 seconds. The target may be slow or unreachable from this service."
                    }
                except Exception as e:
                    import traceback
                    print(f"Error scanning {d}: {e}")
                    traceback.print_exc()
                    result = {
                        "domain": d, "final_url": "", "http_status": "", 
                        "cpq_detected": "UNKNOWN", "cpq_vendor": "", 
                        "confidence": "SCAN_FAILED", "score": 0, 
                        "detection_method": "",
                        "scan_time_seconds": 0, "evidence": "No conclusion was reached because the scanner failed.", "error": f"{type(e).__name__}: {e}"
                    }
                return result

        tasks = [asyncio.create_task(process_domain(d)) for d in domains]
        
        completed = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            yield {"event": "result", "data": json.dumps(result)}
            yield {"event": "progress", "data": json.dumps({"total": len(domains), "completed": completed})}
            
        yield {"event": "done", "data": "scan complete"}


@app.post("/api/scan")
async def start_scan(request: Request):
    _, norm_fn = _get_scanner()
    data = await request.json()
    domains_input = data.get("domains", [])
    if isinstance(domains_input, str):
        domains = [d.strip() for d in re.split(r"[,;\s]+", domains_input) if d.strip()]
    else:
        domains = domains_input if isinstance(domains_input, list) else []
        
    normalized_domains = []
    for d in domains:
        n = norm_fn(d)
        if n and n not in normalized_domains:
            normalized_domains.append(n)
            if len(normalized_domains) >= MAX_DOMAINS_PER_REQUEST:
                break
            
    deep_scan = data.get("deep_scan", False)
    
    return EventSourceResponse(scan_domain_generator(normalized_domains, deep_scan=deep_scan))

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), deep_scan: str = Form("false")):
    _, norm_fn = _get_scanner()
    content = await file.read()
    deep_scan_bool = deep_scan.lower() == "true"
    
    text = content.decode("utf-8-sig", errors="ignore")
    stream = io.StringIO(text)
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(stream, dialect=dialect)
    heads = reader.fieldnames or []
    lookup = {h.lower().strip(): h for h in heads}
    
    col = next((lookup[x] for x in ("domain","domains","website","website_url","url","company_domain","company website") if x in lookup), None)
    if not col and heads:
        col = heads[0]
        
    normalized_domains = []
    if col:
        for row in reader:
            d = norm_fn(row.get(col, ""))
            if d and d not in normalized_domains:
                normalized_domains.append(d)
                if len(normalized_domains) >= MAX_DOMAINS_PER_REQUEST:
                    break
                
    return EventSourceResponse(scan_domain_generator(normalized_domains, deep_scan=deep_scan_bool))

@app.get("/healthz")
async def healthcheck():
    return {"status": "ok", "service": "cpq-detector"}

# Mount the React static files
import os
ui_dist = os.path.join(os.path.dirname(__file__), "ui", "dist")
if os.path.isdir(ui_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(ui_dist, "assets")), name="assets")
    
    @app.get("/")
    @app.head("/")
    async def serve_index():
        return FileResponse(os.path.join(ui_dist, "index.html"))

    @app.get("/{catchall:path}")
    async def serve_react_app(catchall: str):
        requested_file = os.path.join(ui_dist, catchall)
        if os.path.isfile(requested_file):
            return FileResponse(requested_file)
        return FileResponse(os.path.join(ui_dist, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
