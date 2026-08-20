import asyncio, aiohttp, types, time
from cpq_detector import scan

async def main():
    args = types.SimpleNamespace(timeout=10, scan_scripts=True, deep_scan=False, scan_paths=True)
    async with aiohttp.ClientSession() as s:
        domains = ['tenneco.com', 'elsewedyelectric.com']
        for domain in domains:
            start = time.time()
            print(f"Scanning {domain}...")
            res = await scan(s, domain, args)
            print(f"Result for {domain}: {res}")
            print(f"Total time: {time.time() - start:.2f}s\n")

if __name__ == "__main__":
    asyncio.run(main())
