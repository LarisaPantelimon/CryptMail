import asyncio
import socketio
import aiohttp
import ssl

async def test_socketio():
    # Creează un context SSL care ignoră verificarea certificatului
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Configurează o sesiune aiohttp cu SSL dezactivat
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    http_session = aiohttp.ClientSession(connector=connector)

    # Inițializează clientul SocketIO cu sesiunea personalizată
    sio = socketio.AsyncClient(http_session=http_session)
    
    @sio.on('connect')
    async def on_connect():
        print("Connected to SocketIO:", sio.sid)

    @sio.on('connected')
    async def on_connected(data):
        print("Received connected event:", data)

    @sio.on('disconnect')
    async def on_disconnect():
        print("Disconnected")
        await http_session.close()

    await sio.connect('wss://mobile-backend:6000', socketio_path='/mobile/')
    await sio.wait()

asyncio.run(test_socketio())
