# CPQ Detector

Detects public evidence of CPQ and B2B commerce platforms from pages, assets,
headers, common configurator routes, subdomains, and (optionally) linked pages.
It reports vendor-specific evidence separately from generic CPQ evidence.

## Run locally

```powershell
python -m pip install -r requirements.txt
cd ui; npm ci; npm run build; cd ..
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`. The health endpoint is `GET /healthz`.

## Deploy to Render

Connect this repository as a Web Service and Render will use `render.yaml`.
The build creates the React bundle, and the FastAPI app serves it on the same
origin. No `VITE_API_URL` setting is required. The API limits a request to 250
unique domains to protect a single service instance; split larger lists into
separate uploads.

Websites that block shared cloud IP addresses return HTTP 401, 403, or 429. If
your organization has an approved egress proxy, configure `HTTPS_PROXY` (and
optionally `HTTP_PROXY`) in Render environment variables; the scanner honors
those standard variables. Without authorized access, those rows must remain
`ACCESS_RESTRICTED` rather than being misreported as non-CPQ.

## CLI batch scan

```powershell
python cpq_detector.py domains.csv --deep-scan --workers 10
```

Use `--no-path-scan` for a faster, lower-recall run. Results include the exact
evidence snippet so generic matches can be reviewed rather than treated as a
vendor confirmation.
