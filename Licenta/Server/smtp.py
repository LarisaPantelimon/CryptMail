import asyncio
import ssl
import json
import socket
from s3_client import S3Client

class MySMTPServer:
    def __init__(self):
        self.s3_client = S3Client()
        self.actions = {
            "send_email": self.handle_send_email,
        }

    async def initialize(self):
        try:
            await self.s3_client.initialize()
            print("MySMTPServer initialized with MinIO")
        except Exception as e:
            print(f"Error initializing MySMTPServer: {e}")
            raise

    async def close(self):
        try:
            await self.s3_client.close()
            print("MySMTPServer closed")
        except Exception as e:
            print(f"Error closing MySMTPServer: {e}")
            raise

    async def handle_client(self, reader, writer):
        try:
            buffer = b""
            while True:
                chunk = await reader.read(131072)  # 128KB chunks
                if not chunk:
                    break
                buffer += chunk
                print(f"Read {len(chunk)} bytes")

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    try:
                        request = json.loads(line.decode())
                        action = request.get("action")
                        print(f"Action type: {action}")
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error: {e}")
                        writer.write(b"* BAD Invalid JSON format\r\n")
                        await writer.drain()
                        continue

                    if action in self.actions:
                        response = await self.actions[action](request)
                    else:
                        response = {"error": "Unknown action"}

                    writer.write(json.dumps(response).encode() + b"\r\n")
                    await writer.drain()

            if buffer:
                try:
                    request = json.loads(buffer.decode())
                    action = request.get("action")
                    print(f"Action type: {action}")
                    if action in self.actions:
                        response = await self.actions[action](request)
                    else:
                        response = {"error": "Unknown action"}
                    writer.write(json.dumps(response).encode() + b"\r\n")
                    await writer.drain()
                except json.JSONDecodeError as e:
                    print(f"JSON decode error on remaining buffer: {e}")
                    writer.write(b"* BAD Invalid JSON format\r\n")
                    await writer.drain()

        except ConnectionResetError:
            print("Connection reset by client.")
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_send_email(self, request):
        email_id_sent = request.get("email_id_sent")
        email_id_received = request.get("email_id_received")
        mime_message = request.get("mime_message")  # Base64 string
        mime_message_for_me = request.get("mime_message_for_me")  # Base64 string

        filename1 = f"Sent/{email_id_sent}-email.txt"
        filename2 = f"Received/{email_id_received}-email.txt"

        try:
            # Log sizes before decoding
            print(f"mime_message size (Base64): {len(mime_message) / 1024 / 1024:.2f} MB")
            print(f"mime_message_for_me size (Base64): {len(mime_message_for_me) / 1024 / 1024:.2f} MB")

            # S3Client.upload_mime_message handles Base64 decoding
            await self.s3_client.upload_mime_message(mime_message, filename2)
            await self.s3_client.upload_mime_message(mime_message_for_me, filename1)

            return {"success": True}
        except Exception as e:
            print(f"Error sending email to MinIO: {e}")
            return {"success": False, "error": f"Failed to send email: {str(e)}"}

async def main():
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(
        certfile='/etc/letsencrypt/live/cryptmail.stud.fsisc.ro/fullchain.pem',
        keyfile='/etc/letsencrypt/live/cryptmail.stud.fsisc.ro/privkey.pem'
    )
    server = MySMTPServer()
    try:
        await server.initialize()
        server_coroutine = await asyncio.start_server(
            server.handle_client, '0.0.0.0', 587, ssl=ssl_context,
            backlog=100, reuse_address=True
        )
        # Optionally increase receive buffer size
        for sock in server_coroutine.sockets:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)  # 128KB
            actual_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            print(f"Set SO_RCVBUF to 10485760 bytes, actual size: {actual_size} bytes")
        print("SMTP server running on port 587 with SSL")

        async with server_coroutine:
            await server_coroutine.serve_forever()
    except asyncio.CancelledError:
        print("SMTP server stopped.")
    except Exception as e:
        print(f"Server startup failed: {e}")
    finally:
        await server.close()

if __name__ == "__main__":
    asyncio.run(main())