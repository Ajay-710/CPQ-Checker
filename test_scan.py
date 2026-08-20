import asyncio, aiohttp, types, time
from cpq_detector import scan

async def main():
    async with aiohttp.ClientSession() as s:
        print("--- Standard Scan ---")
        args1 = types.SimpleNamespace(timeout=10, scan_scripts=True, deep_scan=False, scan_paths=False, scan_subdomains=False)
        t0 = time.time()
        res1 = await scan(s, 'universal-robots.com', args1)
        print(f"Standard: {res1.get('confidence')} | {res1.get('cpq_vendor')} | time={time.time()-t0:.2f}s")
        
        print("\n--- Deep Scan ---")
        args2 = types.SimpleNamespace(timeout=10, scan_scripts=True, deep_scan=True, scan_paths=True, scan_subdomains=True)
        t0 = time.time()
        res2 = await scan(s, 'universal-robots.com', args2)
        print(f"Deep: {res2.get('confidence')} | {res2.get('cpq_vendor')} | time={time.time()-t0:.2f}s")

if __name__ == '__main__':
    asyncio.run(main())
