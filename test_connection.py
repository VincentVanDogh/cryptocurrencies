import asyncio

async def main():
    reader, writer = await asyncio.open_connection('127.0.0.1', 18018)
    print("Connected!")
    # Read hello message
    hello = await reader.readline()
    print("Received:", hello.decode().strip())
    # Send getpeers
    writer.write(b'{"type":"getpeers"}\n')
    await writer.drain()
    response = await reader.readline()
    print("Received:", response.decode().strip())
    writer.close()
    await writer.wait_closed()

asyncio.run(main())