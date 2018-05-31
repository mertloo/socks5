import asyncio, socket, struct, ipaddress, time, errno


async def pipe(reader, writer):
    while 1:
        data = await reader.read(4096)
        if not data:
            break
        writer.write(data)
        await writer.drain()
    # TBD: elegant shutdown
    writer.close()

def elapsed(fmt, stime, limit=1):
    el = time.time() - stime
    if el > limit:
        print(fmt % el)

async def socks5_handle(reader, writer):
    # ADDR TIME
    tm_nego = time.time()
    auth_meth = await reader.read(3)
    writer.write(b'\x05\x00')
    await writer.drain()
    elapsed('NEGO elapsed %f', tm_nego)
    # --

    # ADDR TIME
    tm_addr = time.time()
    _ = await reader.read(3)
    addrtyp = await reader.read(1)
    addrlen = await reader.read(1)
    bhost = await reader.read(ord(addrlen))
    bport = await reader.read(2)
    elapsed('ADDR RECV elapsed %f', tm_addr)
    # --

    # ADDR PARSE (IGNORE)
    host = bhost
    port = struct.unpack('>H', bport)[0]
    loop = asyncio.get_event_loop()
    # --

    # REMOTE TIME
    tm_remote = time.time()
    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
    except OSError as exc:
        if exc.args[0] == errno.ETIMEDOUT:
            writer.close()
            elapsed('REMOTE TIMEDOUT', time.time())
            return
        raise
    elapsed('REMOTE elapsed %f', tm_remote)
    # --

    # PIPE TIME
    tm_pipe = time.time()
    writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10')
    await writer.drain()
    loop.create_task(pipe(reader, remote_writer))
    loop.create_task(pipe(remote_reader, writer))
    elapsed('PIPE CREATE elapsed %f', tm_pipe)
    # PIPE TIME


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    bind_listen = asyncio.start_server(socks5_handle, host='127.0.0.1', port=1973)
    server = loop.run_until_complete(bind_listen)
    try:
        loop.run_forever()
    finally:
        loop.close()
        server.close()

