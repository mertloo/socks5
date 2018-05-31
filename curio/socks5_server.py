from curio import run, spawn, TaskGroup
from curio.socket import *
import struct
from shadowsocks import encrypt as encryptx
import curio


async def echo_server(address):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(5)
    print('Server listening at', address)
    async with sock:
        while True:
            client, addr = await sock.accept()
            await spawn(echo_client, client, addr, daemon=True)

async def echo_client(client, addr):
    print('accept:', addr)
    async with client:
        data = await client.recv(3)
        assert data == b'\x05\x01\x00', 'auth err'
        await client.sendall(b'\x05\x00')
        data = await client.recv(5)
        assert data[:4] == b'\x05\x01\x00\x03', 'addr1 err'
        ln = data[4]
        data = await client.recv(data[4]+2)
        remote = socket(AF_INET, SOCK_STREAM)
        host, port = '', 16813
        await remote.connect((host, port))
        addr_data = b'\x03'+chr(ln).encode()+data
        enc = encryptx.Encryptor('woshimima1234', 'aes-256-cfb')
        await remote.sendall(enc.encrypt(addr_data))
        await client.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10')
        async with TaskGroup() as group:
            await group.spawn(pipe, client, remote, enc.encrypt)
            await group.spawn(pipe, remote, client, enc.decrypt)
            print('pipe: %r <-> %r' % tuple([s.getsockname() for s in (client, remote)]))
    print('closed:', addr)

async def pipe(src, dst, crypt):
    while 1:
        data = await src.recv(1024)
        if not data:
            break
        await dst.sendall(crypt(data))


if __name__ == '__main__':
    run(echo_server, ('',25000))
