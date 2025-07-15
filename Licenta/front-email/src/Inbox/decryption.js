import pako from "pako";
import asn1 from "asn1.js";
import { Buffer } from "buffer";
function base64ToBytes(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// Convert hex to Uint8Array
function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Convert Uint8Array to hex
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseFinalMessage(base64Message) {
    try {
        if (typeof base64Message !== 'string' || !base64Message.trim()) {
            throw new Error('Invalid Base64 message: must be a non-empty string');
        }
        if (!/^[A-Za-z0-9+/=]+$/.test(base64Message)) {
            //console.error('Base64 string contains invalid characters');
            throw new Error('Invalid Base64 message: contains invalid characters');
        }
        let bytes;
        try {
            bytes = Buffer.from(base64Message, 'base64');
        } catch (decodeError) {
            //console.error('Base64 decoding failed:', decodeError);
            throw new Error('Failed to decode Base64 message');
        }
        //console.log('Base64 Input Length:', base64Message.length);
        //console.log('Parsed Bytes Size:', bytes.length / 1024 / 1024, 'MB');
        //console.log('First 16 Bytes (Hex):', bytesToHex(bytes.slice(0, 16)));

        if (bytes.length < 4) {
            //console.error('Buffer too short:', bytes.length, 'bytes');
            throw new Error('Invalid format: buffer too short for key_id length');
        }

        let offset = 0;
        const dataView = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
        const keyIdLength = dataView.getUint32(offset, false);
        //console.log('Raw keyIdLength Bytes:', bytesToHex(bytes.slice(offset, offset + 4)));
        //console.log('Parsed keyIdLength:', keyIdLength);
        if (keyIdLength > 1024 || keyIdLength < 1) {
            throw new Error(`Invalid key_id length: ${keyIdLength} (must be 1–1024)`);
        }
        offset += 4;

        if (offset + keyIdLength > bytes.length) {
            //console.error('Buffer too short for key_id:', { offset, keyIdLength, bytesLength: bytes.length });
            throw new Error('Invalid format: missing key_id');
        }
        const keyId = new TextDecoder().decode(bytes.slice(offset, offset + keyIdLength));
        offset += keyIdLength;

        if (offset + 4 > bytes.length) {
            //console.error('Buffer too short for key length:', { offset, bytesLength: bytes.length });
            throw new Error('Invalid format: missing key length');
        }
        const keyLength = dataView.getUint32(offset, false);
        //console.log('Raw keyLength Bytes:', bytesToHex(bytes.slice(offset, offset + 4)));
        //console.log('Parsed keyLength:', keyLength);
        if (keyLength > 4096 || keyLength < 1) {
            throw new Error(`Invalid key length: ${keyLength} (must be 1–4096)`);
        }
        offset += 4;

        if (offset + keyLength > bytes.length) {
            //console.error('Buffer too short for encrypted key:', { offset, keyLength, bytesLength: bytes.length });
            throw new Error('Invalid format: missing encrypted key');
        }
        const encryptedKey = bytes.slice(offset, offset + keyLength);
        offset += keyLength;

        if (offset > bytes.length) {
            //console.error('No ciphertext remaining:', { offset, bytesLength: bytes.length });
            throw new Error('Invalid format: missing ciphertext');
        }
        const ciphertext = bytes.slice(offset);

        //console.log('Parsed key_id:', keyId);
        //console.log('Parsed encrypted_symmetric_key length:', encryptedKey.length);
        //console.log('Parsed ciphertext length:', ciphertext.length / 1024 / 1024, 'MB');

        return {
            key_id: keyId,
            encrypted_symmetric_key: encryptedKey,
            ciphertext: ciphertext
        };
    } catch (error) {
        //console.error('Error parsing Base64 message:', error);
        throw new Error(`Failed to parse MIME message: ${error.message}`);
    }
}

// 2. Verify Key ID
function verifyPubkeyOfReceiver(finalForm, myKeyId) {
    //console.log('Message key_id:', finalForm.key_id);
    //console.log('My key_id:', myKeyId);
    return finalForm.key_id === myKeyId;
}

const RSAPrivateKeyASN = asn1.define("RSAPrivateKey", function () {
    this.seq().obj(
        this.key("version").int(),
        this.key("n").int(),
        this.key("e").int(),
        this.key("d").int(),
        this.key("p").int(),
        this.key("q").int(),
        this.key("dp").int(),
        this.key("dq").int(),
        this.key("qi").int()
    );
});

function convertPkcs1ToPkcs8(pemPrivateKey) {
    // Decode Base64
    const base64Key = pemPrivateKey
        .replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, "");
    const derKey = Buffer.from(atob(base64Key), "binary"); 

    // Parse PKCS#1
    const rsaKey = RSAPrivateKeyASN.decode(derKey, "der");

    // Convert to PKCS#8
    const PrivateKeyInfoASN = asn1.define("PrivateKeyInfo", function () {
        this.seq().obj(
            this.key("version").int(),
            this.key("algorithm").seq().obj(
                this.key("oid").objid(),
                this.key("params").null_()
            ),
            this.key("privateKey").octstr()
        );
    });

    const privateKeyInfo = PrivateKeyInfoASN.encode({
        version: 0,
        algorithm: { oid: [1, 2, 840, 113549, 1, 1, 1], params: null },
        privateKey: RSAPrivateKeyASN.encode(rsaKey, "der")
    }, "der");

    return new Uint8Array(privateKeyInfo).buffer;
}

function parsePemKey(pemKey) {
    if (pemKey.includes("-----BEGIN RSA PRIVATE KEY-----")) {
        // //console.log("Detected PKCS#1 Key - Converting to PKCS#8...");
        return convertPkcs1ToPkcs8(pemKey);
    } else if (pemKey.includes("-----BEGIN PRIVATE KEY-----")) {
        // //console.log("Detected PKCS#8 Key - Importing...");
        const base64Key = pemKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
        return Uint8Array.from(atob(base64Key), c => c.charCodeAt(0)).buffer;
    } else {
        throw new Error("Invalid PEM key format. Expected PKCS#1 or PKCS#8.");
    }
}

async function importRsaPrivateKey(pemPrivateKey) {
    try {
        const privateKeyBuffer = parsePemKey(pemPrivateKey);
        // console.log("Parsed Private Key Buffer:", privateKeyBuffer);

        // Log the key buffer as a hex string for debugging
        // console.log("Private Key Buffer (Hex):", bytesToHex(privateKeyBuffer));
        // console.log("------------------- SO THE KEY IS CONVERTED -------------------");

        const privateKey = await crypto.subtle.importKey(
            "pkcs8", // PKCS#8 for private keys
            privateKeyBuffer,
            { name: "RSA-OAEP", hash: "SHA-256" }, // RSA-OAEP for decryption
            false,
            ["decrypt"]
        );

        // console.log("RSA Private Key Imported Successfully:", privateKey);
        return privateKey;
    } catch (error) {
        //console.error("Error importing RSA private key:", error);
        throw error;
    }
}

// 3. Decrypt Symmetric Key with RSA (Web Crypto API)
async function decryptSymmetricKeyWithRsa(encryptedData, privateKey) {
    try {
        if (!encryptedData?.encrypted_symmetric_key) {
            throw new Error('Missing encrypted_symmetric_key');
        }
        const PrivateKey = await importRsaPrivateKey(privateKey);
        const encryptedSymmetricKeyBytes = encryptedData.encrypted_symmetric_key;

        const decryptedBytes = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            PrivateKey,
            encryptedSymmetricKeyBytes
        );

        const decryptedJson = new TextDecoder().decode(decryptedBytes);
        const decryptedData = JSON.parse(decryptedJson);

        return {
            key: decryptedData.key instanceof Uint8Array ? decryptedData.key : hexToBytes(decryptedData.key),
            iv: decryptedData.iv instanceof Uint8Array ? decryptedData.iv : hexToBytes(decryptedData.iv)
        };
    } catch (error) {
        //console.error('Error decrypting symmetric key:', error);
        throw new Error(`Failed to decrypt symmetric key: ${error.message}`);
    }
}

// Decrypt the message
async function decryptMessage(ciphertext, encryptionParams) {
    try {
        // Ensure key and iv are Uint8Array
        const keyBytes = encryptionParams.key instanceof Uint8Array ? encryptionParams.key : hexToBytes(encryptionParams.key);
        const ivBytes = encryptionParams.iv instanceof Uint8Array ? encryptionParams.iv : hexToBytes(encryptionParams.iv);

        // Import the AES-GCM key
        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // Ciphertext is already Uint8Array
        const ciphertextBytes = ciphertext;

        // Decrypt the message
        const decryptedBytes = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBytes
            },
            cryptoKey,
            ciphertextBytes
        );

        // Convert to Uint8Array
        const decryptedUint8Array = new Uint8Array(decryptedBytes);
        return decryptedUint8Array;
    } catch (error) {
        //console.error('Decryption failed:', error);
        throw new Error(`Decryption failed: ${error.message}`);
    }
}


function decompressMessage(compressedMessage) {
    try {
        const uint8Array = compressedMessage instanceof Uint8Array ? compressedMessage : new Uint8Array(compressedMessage);
        //console.log('Input Data Size:', uint8Array.length / 1024 / 1024, 'MB');

        let jsonString;
        try {
            jsonString = pako.inflate(uint8Array, { to: 'string' });
            //console.log('Decompressed Data Length:', jsonString.length);
        } catch (inflateError) {
            //console.log('Decompression failed, assuming uncompressed JSON:', inflateError.message);
            jsonString = new TextDecoder().decode(uint8Array);
        }

        const parsedData = JSON.parse(jsonString);
        if (!parsedData.signature_part || !parsedData.message_part) {
            throw new Error('Invalid decompressed data: missing signature_part or message_part');
        }
        if (!parsedData.signature_part.signature_timestamp || !parsedData.signature_part.leading_octets_of_digest) {
            throw new Error('Invalid signature_part: missing signature_timestamp or leading_octets_of_digest');
        }

        parsedData.message_part = new Uint8Array(parsedData.message_part);
        //console.log('Parsed Message Part Size:', parsedData.message_part.length / 1024 / 1024, 'MB');
        //console.log('Signature Part:', parsedData.signature_part);
        //console.log('Files in Signature Part:', parsedData.signature_part.files || 'None');

        return parsedData;
    } catch (error) {
        //console.error('Decompression or JSON parsing failed:', error);
        throw new Error(`Decompression failed: ${error.message}`);
    }
}

// 6. Hash Calculation (Web Crypto API)
async function calculateHashMessage(message) {
    // //console.log("-------------------------------1. SI AM INTRAAAAT---------------------------------\n");
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-512", data);
    return bytesToHex(new Uint8Array(hashBuffer));
}

// Get first two octets of hash
function getLeadingTwoOctets(hashResult) {
    return hashResult.substring(0, 4);
}

// 6.1 First Verification
async function firstVerification(decryptedMessage) {
    try {
        if (!decryptedMessage?.message_part || !decryptedMessage?.signature_part) {
            throw new Error('Invalid decrypted message: missing message_part or signature_part');
        }
        const messagePart = decryptedMessage.message_part; // Uint8Array
        const signaturePart = decryptedMessage.signature_part;

        // Reconstruct metadata from signature_part
        const encoder = new TextEncoder();
        const metadata = encoder.encode(
            JSON.stringify({
                files: signaturePart.files || [], // Fallback to empty array
                timestamp: signaturePart.signature_timestamp
            })
        );

        // Combine metadata and message_part (raw bytes)
        const combined = new Uint8Array(metadata.length + messagePart.length);
        combined.set(metadata, 0);
        combined.set(messagePart, metadata.length);

        // Calculate SHA-512 hash
        const hashBuffer = await crypto.subtle.digest('SHA-512', combined);
        const hashMesaj = bytesToHex(new Uint8Array(hashBuffer));

        // Compare leading two octets
        const recalculatedLeadingTwoOctets = getLeadingTwoOctets(hashMesaj);
        const receivedLeadingTwoOctets = signaturePart.leading_octets_of_digest;

        //console.log('Full Recalculated Hash:', hashMesaj);
        //console.log('Recalculated Leading Two Octets:', recalculatedLeadingTwoOctets);
        //console.log('Received Leading Two Octets:', receivedLeadingTwoOctets);
        //console.log('Combined Data Size:', combined.length / 1024, 'KB');
        // console.log('Metadata:', JSON.stringify({
        //     files: signaturePart.files || [],
        //     timestamp: signaturePart.signature_timestamp
        // }));

        if (recalculatedLeadingTwoOctets === receivedLeadingTwoOctets) {
            //console.log('First verification passed: Leading two octets match.');
            return true;
        } else {
            //console.error('First verification failed: Leading two octets do not match.');
            throw new Error('First verification failed: Leading octets mismatch');
        }
    } catch (error) {
        //console.error('Error during first verification:', error);
        throw new Error(`First verification error: ${error.message}`);
    }
}

// 7. Verify Signature with RSA-PSS (Web Crypto API)
function parsePemKeyPublic(pemKey) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";

    if (!pemKey.includes(pemHeader) || !pemKey.includes(pemFooter)) {
        throw new Error("Invalid PEM format for public key.");
    }

    // Extract only the Base64-encoded part
    const base64Key = pemKey
        .replace(pemHeader, "")
        .replace(pemFooter, "")
        .replace(/\s+/g, ""); // Remove spaces and newlines

    // Convert Base64 to ArrayBuffer
    const binaryKey = atob(base64Key);
    return Uint8Array.from(binaryKey, (c) => c.charCodeAt(0)).buffer; // Return as ArrayBuffer
}

async function verifyMessage(message, rsaPublicKey) {
    try {
        if (!rsaPublicKey || typeof rsaPublicKey !== "string") {
            throw new Error("Public key is missing or invalid.");
        }
        if (!rsaPublicKey.includes("-----BEGIN PUBLIC KEY-----") || !rsaPublicKey.includes("-----END PUBLIC KEY-----")) {
            throw new Error("Invalid PEM format for public key.");
        }

        // Import public key
        const publicKeyBuffer = parsePemKeyPublic(rsaPublicKey);
        const publicKey = await crypto.subtle.importKey(
            "spki",
            publicKeyBuffer,
            { name: "RSA-PSS", hash: "SHA-512" },
            false,
            ["verify"]
        );

        // Reconstruct metadata from signature_part
        const signaturePart = message.signature_part;
        const messagePart = message.message_part; // Uint8Array
        const encoder = new TextEncoder();
        const metadata = encoder.encode(
            JSON.stringify({
                files: signaturePart.files || [],
                timestamp: signaturePart.signature_timestamp
            })
        );

        // Combine metadata and message_part (raw bytes)
        const combined = new Uint8Array(metadata.length + messagePart.length);
        combined.set(metadata, 0);
        combined.set(messagePart, metadata.length);

        // Calculate SHA-512 hash
        const hashBuffer = await crypto.subtle.digest("SHA-512", combined);
        const hashMesaj = bytesToHex(new Uint8Array(hashBuffer));

        // Prepare signature
        const signatureToVerify = hexToBytes(signaturePart.signature);

        // Verify signature against the hash
        const isValid = await window.crypto.subtle.verify(
            {
                name: "RSA-PSS",
                saltLength: 32
            },
            publicKey,
            signatureToVerify,
            encoder.encode(hashMesaj) // Hash as text
        );

        //console.log('Verification Hash:', hashMesaj);
        //console.log('Signature Verification Result:', isValid);
        //console.log('Public Key ID:', signaturePart.public_key_id);
        // console.log('Metadata Used:', JSON.stringify({
        //     files: signaturePart.files || [],
        //     timestamp: signaturePart.signature_timestamp
        // }));

        return isValid;
    } catch (error) {
        //console.error("Signature verification failed:", error);
        throw new Error(`Signature verification failed: ${error.message}`);
    }
}

export {
    parseFinalMessage,
    verifyPubkeyOfReceiver,
    decryptSymmetricKeyWithRsa,
    decryptMessage,
    decompressMessage,
    firstVerification,
    verifyMessage
};