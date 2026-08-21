import asyncio, aiohttp, types, time
from cpq_detector import scan

async def main():
    args = types.SimpleNamespace(timeout=20, scan_scripts=True, deep_scan=False, scan_paths=False, scan_subdomains=False)
    connector = aiohttp.TCPConnector(limit=50, limit_per_host=3, ttl_dns_cache=300)
    
    domains = ['solaredge.com', 'universal-robots.com', 'fanucamerica.com']
    
    async with aiohttp.ClientSession(connector=connector) as s:
        for d in domains:
            t0 = time.time()
            print(f"\nScanning {d}...")
            res = await scan(s, d, args)
            print(f"Result for {d}:")
            print(f"  Confidence: {res.get('confidence')}")
            print(f"  Vendor: {res.get('cpq_vendor')}")
            print(f"  Method: {res.get('detection_method')}")
            print(f"  HTTP Status: {res.get('http_status')}")
            print(f"  Time: {time.time()-t0:.2f}s")
            print(f"  Evidence: {res.get('evidence')[:100]}")

if __name__ == '__main__':
    asyncio.run(main())
