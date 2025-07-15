import time
from aiobotocore.session import get_session
from aiobotocore.config import AioConfig
from botocore.exceptions import NoCredentialsError, ClientError
import base64
import os
from dotenv import load_dotenv

# Încarca variabilele din .env
load_dotenv()

class S3Client:
    def __init__(self):
        self.bucket_name = os.getenv("S3_BUCKET", "licenta2025")
        self.session = get_session()
        self.s3_client = None
        self.endpoint_url = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
        self.access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        self._initialized = False

    async def initialize(self):
        try:
            client_cm = self.session.create_client(
                's3',
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                config=AioConfig(
                    retries={'max_attempts': 5},
                    connect_timeout=120,
                    read_timeout=120,
                    signature_version='s3v4'
                )
            )
            self.s3_client = await client_cm.__aenter__()
            print(f"Initialized aiobotocore MinIO client: {type(self.s3_client)}")
            self._initialized = True

            try:
                await self.s3_client.head_bucket(Bucket=self.bucket_name)
                print(f"Bucket '{self.bucket_name}' exists")
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    print(f"Creating bucket '{self.bucket_name}'")
                    await self.s3_client.create_bucket(Bucket=self.bucket_name)
                else:
                    raise
        except NoCredentialsError:
            print("Error: MinIO credentials invalid. Check username and password.")
            raise
        except Exception as e:
            print(f"Error initializing aiobotocore MinIO client: {e}")
            raise

    async def close(self):
        if self.s3_client and self._initialized:
            try:
                await self.s3_client.__aexit__(None, None, None)
                print("Closed aiobotocore MinIO client")
            except Exception as e:
                print(f"Error closing aiobotocore MinIO client: {e}")
            finally:
                self.s3_client = None
                self._initialized = False

    def _ensure_initialized(self):
        if not self._initialized or self.s3_client is None:
            raise RuntimeError("S3Client is not initialized. Call initialize() first.")

    async def upload_mime_message(self, mime_message, filename):
        try:
            self._ensure_initialized()
            start_time = time.time()
            if isinstance(mime_message, str):
                mime_message = base64.b64decode(mime_message)  # Decode Base64 string to bytes
            print(f"Uploading {filename}, size: {len(mime_message) / 1024 / 1024:.2f} MB")

            response = await self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=filename,
                Body=mime_message
            )
            elapsed_time = time.time() - start_time
            print(f"MIME message uploaded to MinIO: {filename} in {elapsed_time:.2f} seconds")
            return response
        except ClientError as e:
            print(f"Error uploading MIME message to MinIO {filename}: {e.response['Error']['Message']}")
            raise
        except Exception as e:
            print(f"Error uploading MIME message to MinIO {filename}: {e}")
            raise

    async def fetch_email(self, filename):
        try:
            self._ensure_initialized()
            obj = await self.s3_client.get_object(Bucket=self.bucket_name, Key=filename)
            async with obj['Body'] as stream:
                mime_message = await stream.read()  # Bytes
            print(f"Fetched {filename}, size: {len(mime_message) / 1024 / 1024:.2f} MB")
            base64_message = base64.b64encode(mime_message).decode('utf-8')
            print(f"Fetched {filename}, Base64 size: {len(base64_message) / 1024 / 1024:.2f} MB")
            return base64_message
        except ClientError as e:
            print(f"Error retrieving MIME message from MinIO {filename}: {e.response['Error']['Message']}")
            raise
        except Exception as e:
            print(f"Error retrieving MIME message from MinIO {filename}: {e}")
            raise

    async def delete_mime_message(self, email_id, folder):
        try:
            self._ensure_initialized()
            file_name = f"{folder}{email_id}-email.txt"
            await self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=file_name
            )
            print(f"MIME message deleted from MinIO: {file_name}")
        except ClientError as e:
            print(f"Error deleting MIME message from MinIO {file_name}: {e.response['Error']['Message']}")
            raise
        except Exception as e:
            print(f"Error deleting MIME message from MinIO {file_name}: {e}")
            raise

    async def delete_all_emails(self, filestoDelete):
        try:
            self._ensure_initialized()
            for file_name in filestoDelete:
                await self.s3_client.delete_object(
                    Bucket=self.bucket_name,
                    Key=file_name
                )
                print(f"MIME message deleted from MinIO: {file_name}")
            return True
        except ClientError as e:
            print(f"Error deleting MIME message from MinIO {file_name}: {e.response['Error']['Message']}")
            raise
        except Exception as e:
            print(f"Error deleting MIME message from MinIO {file_name}: {e}")
            raise

    async def check_s3_object(self, filename):
        try:
            self._ensure_initialized()
            obj = await self.s3_client.get_object(Bucket=self.bucket_name, Key=filename)
            async with obj['Body'] as stream:
                content_length = len(await stream.read())
            print(f"Size of {filename}: {content_length / 1024 / 1024:.2f} MB")
            return content_length
        except ClientError as e:
            print(f"Error accessing {filename}: {e.response['Error']['Message']}")
            raise
        except Exception as e:
            print(f"Error accessing {filename}: {e}")
            raise