import asyncio
import aiohttp
import types
from cpq_detector import scan

async def main():
    args = types.SimpleNamespace(timeout=20, scan_scripts=True, deep_scan=True)
    async with aiohttp.ClientSession() as s:
        res1 = await scan(s, 'lghvac.com', args)
        print("LGHVAC:", res1)

if __name__ == "__main__":
    asyncio.run(main())
