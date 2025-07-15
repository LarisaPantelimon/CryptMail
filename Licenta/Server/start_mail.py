import asyncio
import subprocess

async def run_server(script):
    process = await asyncio.create_subprocess_exec("python", script)
    await process.wait()

async def main():
    await asyncio.gather(
        run_server("imap.py"),
        run_server("smtp.py")
    )

if __name__ == "__main__":
    asyncio.run(main())