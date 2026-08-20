import asyncio
import csv
import io
import types
from typing import List
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sse_starlette.sse import EventSourceResponse
import aiohttp

# Import functions from cpq_detector
from cpq_detector import scan, norm

app = FastAPI(title="CPQ Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def scan_domain_generator(domains: List[str], deep_scan: bool = False, timeout: int = 20):
    args = types.SimpleNamespace(timeout=timeout, scan_scripts=True, deep_scan=deep_scan)
    
    # We will use a semaphore to limit concurrency
    semaphore = asyncio.Semaphore(10)
    
    connector = aiohttp.TCPConnector(limit=20, limit_per_host=3, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        
        async def process_domain(d):
            async with semaphore:
                try:
                    result = await scan(session, d, args)
                except Exception as e:
                    import traceback
                    print(f"Error scanning {d}: {e}")
                    traceback.print_exc()
                    result = {
                        "domain": d, "final_url": "", "http_status": "", 
                        "cpq_detected": "NO", "cpq_vendor": "", 
                        "confidence": "NOT_DETECTED", "score": 0, 
                        "detection_method": "", "evidence": "", 
                        "scan_time_seconds": 0, "error": f"{type(e).__name__}: {e}"
                    }
                return result

        tasks = [asyncio.create_task(process_domain(d)) for d in domains]
        
        # As tasks complete, yield them to the SSE stream
        for coro in asyncio.as_completed(tasks):
            result = await coro
            import json
            yield {"event": "result", "data": json.dumps(result)}
            
        yield {"event": "done", "data": "scan complete"}


@app.post("/api/scan")
async def start_scan(request: Request):
    data = await request.json()
    domains_input = data.get("domains", [])
    if isinstance(domains_input, str):
        domains = [d.strip() for d in domains_input.split(",") if d.strip()]
    else:
        domains = domains_input
        
    normalized_domains = []
    for d in domains:
        n = norm(d)
        if n and n not in normalized_domains:
            normalized_domains.append(n)
            
    deep_scan = data.get("deep_scan", False)
    
    return EventSourceResponse(scan_domain_generator(normalized_domains, deep_scan=deep_scan))

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), deep_scan: str = Form("false")):
    content = await file.read()
    deep_scan_bool = deep_scan.lower() == "true"
    
    # Decode CSV
    text = content.decode("utf-8-sig", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    heads = reader.fieldnames or []
    lookup = {h.lower().strip(): h for h in heads}
    
    # Try to find domain column
    col = next((lookup[x] for x in ("domain","domains","website","website_url","url","company_domain","company website") if x in lookup), None)
    if not col and heads:
        col = heads[0]
        
    normalized_domains = []
    if col:
        for row in reader:
            d = norm(row.get(col, ""))
            if d and d not in normalized_domains:
                normalized_domains.append(d)
                
    return EventSourceResponse(scan_domain_generator(normalized_domains, deep_scan=deep_scan_bool))

# Mount the React static files
import os
ui_dist = os.path.join(os.path.dirname(__file__), "ui", "dist")
if os.path.isdir(ui_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(ui_dist, "assets")), name="assets")
    
    @app.get("/{catchall:path}")
    async def serve_react_app(catchall: str):
        # Serve the index.html for any other route to support React Router (if used)
        # Check if the requested file exists in dist, otherwise return index.html
        requested_file = os.path.join(ui_dist, catchall)
        if os.path.isfile(requested_file):
            return FileResponse(requested_file)
        return FileResponse(os.path.join(ui_dist, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
