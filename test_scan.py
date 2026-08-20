import asyncio, aiohttp, types
from cpq_detector import scan

async def main():
    args = types.SimpleNamespace(timeout=20, scan_scripts=True, deep_scan=False)
    async with aiohttp.ClientSession() as s:
        # Test without deep scan - subdomains still always run
        res1 = await scan(s, 'lghvac.com', args)
        print("LGHVAC (no deep):", res1)
        print()
        
        res2 = await scan(s, 'peakscientific.com', args)
        print("PeakScientific:", res2)

if __name__ == "__main__":
    asyncio.run(main())
