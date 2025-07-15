import socketio
import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

sio = socketio.AsyncClient(engineio_logger=True, logger=True)

@sio.event
async def connect():
    logger.info('Connection established!')
    print("Connected to Socket.IO server!")
    await sio.emit('register', {'email': 'testuser@example.com'})

@sio.event
async def disconnect():
    logger.info('Disconnected from server.')
    print("Disconnected from Socket.IO server.")

@sio.event
async def registered(data):
    print(f"Received 'registered' event: {data}")
    logger.info(f"Received 'registered' event: {data}")

@sio.event
async def connected(data):
    print(f"Received 'connected' event: {data}")
    logger.info(f"Received 'connected' event: {data}")

@sio.event
async def encrypted_data(data):
    print(f"Received 'encrypted_data' event: {data}")
    logger.info(f"Received 'encrypted_data' event: {data}")

@sio.event
async def pong(data):
    print(f"Received 'pong' event: {data}")
    logger.info(f"Received 'pong' event: {data}")

@sio.event
async def error(data):
    print(f"Received 'error' event: {data}")
    logger.error(f"Received 'error' event: {data}")

async def main():
    try:
        # --- IMPORTANT CHANGE HERE ---
        # Specify the socketio_path to match your backend's engineio_path
        await sio.connect('http://localhost:6000', socketio_path='/')
        # -----------------------------
        await sio.wait()
    except socketio.exceptions.ConnectionError as e:
        logger.error(f"Failed to connect: {e}")
        print(f"Failed to connect: {e}. Check your backend logs and URL.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    asyncio.run(main())
