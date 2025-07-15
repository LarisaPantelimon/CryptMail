import asyncio
import ssl
import json
from s3_client import S3Client
import base64
import binascii

class MyIMAPServer:
    def __init__(self):
        self.s3_client = S3Client()
        self.actions = {
            "delete_email": self.handle_delete_email,
            "fetch_email_content": self.handle_fetch_email_content,
            "delete_emails_user": self.handle_delete_emails_user,
        }

    async def initialize(self):
        try:
            await self.s3_client.initialize()
            print("MyIMAPServer initialized with MinIO")
        except Exception as e:
            print(f"Error initializing MyIMAPServer: {e}")
            raise

    async def close(self):
        try:
            await self.s3_client.close()
            print("MyIMAPServer closed")
        except Exception as e:
            print(f"Error closing MyIMAPServer: {e}")
            raise

    async def handle_client(self, reader, writer):
        try:
            while True:
                data = await reader.readuntil(b'\n')
                if not data:
                    break
                print("Data received from client:", data.decode())

                try:
                    request = json.loads(data.decode())
                    action = request.get("action")
                    print(f"Request type: {action}")
                except json.JSONDecodeError:
                    writer.write(b"* BAD Invalid JSON format\n")
                    await writer.drain()
                    continue

                if action in self.actions:
                    response = await self.actions[action](request)
                else:
                    response = {"error": "Unknown action"}

                writer.write(json.dumps(response).encode() + b"\n")
                await writer.drain()

        except ConnectionResetError:
            print("Connection reset by client.")
        except asyncio.IncompleteReadError:
            print("Client disconnected unexpectedly.")
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_fetch_email_content(self, request):
        try:
            email_id = request.get("email_id")
            folder = request.get("folder")
            filename = f"{folder}{email_id}-email.txt"

            if not email_id or not folder:
                return {"success": False, "error": "Missing email_id or folder"}

            try:
                email_message = await self.s3_client.fetch_email(filename)
                print(f"Returning Base64 MIME message for {filename}, size: {len(email_message) / 1024 / 1024:.2f} MB")
                return {"success": True, "MimeMessage": email_message}
            except Exception as e:
                print(f"Error fetching email content from MinIO: {e}")
                return {"success": False, "error": f"Failed to fetch email content: {str(e)}"}
        except Exception as e:
            print(f"Error in handle_fetch_email_content: {e}")
            return {"success": False, "error": f"Failed to fetch email content: {str(e)}"}

    async def handle_delete_email(self, request):
        try:
            email_id = request.get("email_id")
            user_email = request.get("email")
            sender = request.get("sender")
            receiver = request.get("receiver")
            print(f"Deleting email {email_id}, user: {user_email}, sender: {sender}, receiver: {receiver}")

            if not email_id:
                return {"success": False, "error": "Missing email ID in the request"}

            deleted = False
            if sender == user_email:
                await self.s3_client.delete_mime_message(email_id, "Sent/")
                print(f"Deleted Sent/{email_id}-email.txt")
                deleted = True
            if user_email == receiver:
                await self.s3_client.delete_mime_message(email_id, "Received/")
                print(f"Deleted Received/{email_id}-email.txt")
                deleted = True
            if sender != user_email:
                await self.s3_client.delete_mime_message(email_id, "Received/")
                print(f"Deleted Received/{email_id}-email.txt")
                deleted = True

            if deleted:
                return {"success": True}
            else:
                return {"success": False, "error": "No email deleted"}
        except Exception as e:
            print(f"Error deleting email from MinIO: {e}")
            return {"success": False, "error": f"Failed to delete email: {str(e)}"}
        
    async def handle_delete_emails_user(self, request):
        try:
            user_email = request.get("email_user")
            email_sent_ids=request.get("email_sent_ids")
            email_received_ids=request.get("email_received_ids")
            

            if not user_email:
                return {"success": False, "error": "Missing email or folder"}

            filestoDelete = []
            if email_sent_ids:  # Check if the email_sent_ids list is not empty
                for email in email_sent_ids:
                    filestoDelete.append(f"Sent/{email}-email.txt")

            if email_received_ids:  # Check if the email_received_ids list is not empty
                for email in email_received_ids:
                    filestoDelete.append(f"Received/{email}-email.txt")

            
            deleted = await self.s3_client.delete_all_emails(filestoDelete)
            if deleted:
                return {"success": True}
            else:
                return {"success": False, "error": "No emails deleted"}
        except Exception as e:
            print(f"Error deleting emails from MinIO: {e}")
            return {"success": False, "error": f"Failed to delete emails: {str(e)}"}

async def main():
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(
        certfile='/etc/letsencrypt/live/cryptmail.stud.fsisc.ro/fullchain.pem',
        keyfile='/etc/letsencrypt/live/cryptmail.stud.fsisc.ro/privkey.pem'
    )

    server = MyIMAPServer()
    try:
        await server.initialize()
        server_coroutine = await asyncio.start_server(server.handle_client, '0.0.0.0', 993, ssl=ssl_context)
        print("IMAP server running on port 993 with SSL")

        async with server_coroutine:
            await server_coroutine.serve_forever()
    except asyncio.CancelledError:
        print("IMAP server stopped.")
    except Exception as e:
        print(f"Server startup failed: {e}")
    finally:
        await server.close()

if __name__ == "__main__":
    asyncio.run(main())