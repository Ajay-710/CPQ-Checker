import asyncio
import aiohttp
import types
from cpq_detector import scan

async def main():
    args = types.SimpleNamespace(timeout=20, scan_scripts=True, deep_scan=False)
    async with aiohttp.ClientSession() as s:
        res1 = await scan(s, 'shield.ai', args)
        print("Shield AI:", res1)
        res2 = await scan(s, 'peakscientific.com', args)
        print("Peak Scientific:", res2)

if __name__ == "__main__":
    asyncio.run(main())
