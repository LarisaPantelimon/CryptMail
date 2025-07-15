import zlib
import base64

def compress_message(message: str) -> str:
    """
    Compresses a string message using zlib and encodes it in base64.

    :param message: The original message as a string.
    :return: The compressed message as a base64-encoded string.
    """
    compressed_data = zlib.compress(message.encode("utf-8"))
    return base64.b64encode(compressed_data).decode("utf-8")

def decompress_message(compressed_message: str) -> str:
    """
    Decompresses a base64-encoded zlib-compressed string.

    :param compressed_message: The compressed message as a base64-encoded string.
    :return: The original message as a string.
    """
    compressed_data = base64.b64decode(compressed_message)
    return zlib.decompress(compressed_data).decode("utf-8")


original_message = "This is a test message that will be compressed."

# Compress the message
compressed_string = compress_message(original_message)
print("Compressed:", compressed_string)

# Decompress the message
decompressed_string = decompress_message(compressed_string)
print("Decompressed:", decompressed_string)
