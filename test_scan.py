import asyncio, aiohttp, types, time
from cpq_detector import scan

async def main():
    args = types.SimpleNamespace(timeout=15, scan_scripts=True, deep_scan=False, scan_paths=False, scan_subdomains=False)
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=3, ttl_dns_cache=300)
    semaphore = asyncio.Semaphore(4)
    
    domains = [
        'nishat.net', 'bostondynamics.com', 'solisinverters.com',
        'universal-robots.com', 'chintglobal.com', 'yunustextile.com',
        'fanucamerica.com', 'solaredge.com', 'tridentindia.com',
        'goodwe.com', 'vitra.com', 'acimotors-bd.com', 'elsewedyelectric.com',
        'tenneco.com', 'msnlabs.com'
    ]
    
    async with aiohttp.ClientSession(connector=connector) as s:
        async def run_d(d):
            async with semaphore:
                t0 = time.time()
                res = await scan(s, d, args)
                print(f"[{time.time()-t0:.2f}s] {d}: {res.get('confidence')} | {res.get('cpq_vendor')} | {res.get('evidence')[:60]}")
                return res

        t_start = time.time()
        print(f"Starting batch test of {len(domains)} domains with Semaphore(4)...")
        results = await asyncio.gather(*[run_d(d) for d in domains])
        print(f"\nALL {len(domains)} DOMAINS FINISHED in {time.time()-t_start:.2f} seconds!")
        
        failed = [r for r in results if r.get('confidence') == 'SCAN_FAILED']
        print(f"Failed count: {len(failed)} / {len(domains)}")

if __name__ == '__main__':
    asyncio.run(main())
