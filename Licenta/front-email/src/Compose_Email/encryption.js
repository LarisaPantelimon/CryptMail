import pako from "pako";
import asn1 from "asn1.js";
import { Buffer } from "buffer";

async function hexToBytes(hex) {
    if (!hex || typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
        throw new Error("Invalid hex string provided to hexToBytes: " + hex);
    }
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Helper function to convert bytes to hex
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Helper function to parse PEM-encoded keys
function parsePemKey(pemKey) {
    const pemHeader = "-----BEGIN RSA PRIVATE KEY-----";
    const pemFooter = "-----END RSA PRIVATE KEY-----";
    const pemPublicHeader = "-----BEGIN PUBLIC KEY-----";
    const pemPublicFooter = "-----END PUBLIC KEY-----";

    if (pemKey.includes(pemHeader)) {
        pemKey = pemKey.replace(pemHeader, "").replace(pemFooter, "").replace(/\s+/g, "");
    } else if (pemKey.includes(pemPublicHeader)) {
        pemKey = pemKey.replace(pemPublicHeader, "").replace(pemPublicFooter, "").replace(/\s+/g, "");
    } else {
        throw new Error("Invalid PEM key format");
    }

    return Uint8Array.from(atob(pemKey), c => c.charCodeAt(0));
}

// Calculate SHA-512 hash
async function calculateHashMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-512", data);
    return bytesToHex(new Uint8Array(hashBuffer));
}

// Get the leading two octets of a hash
function getLeadingTwoOctets(hash) {
    return hash.substring(0, 4);
}

// Sign the hash with the private key
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

    const privateKeyInfo = PrivateKeyInfoASN.encode(
        {
            version: 0,
            algorithm: { oid: [1, 2, 840, 113549, 1, 1, 1], params: null },
            privateKey: RSAPrivateKeyASN.encode(rsaKey, "der"),
        },
        "der"
    );

    return new Uint8Array(privateKeyInfo).buffer;
}

function parsePemKeyprv(pemKey) {
    if (pemKey.includes("-----BEGIN RSA PRIVATE KEY-----")) {
        return convertPkcs1ToPkcs8(pemKey);
    } else if (pemKey.includes("-----BEGIN PRIVATE KEY-----")) {
        const base64Key = pemKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
        return Uint8Array.from(atob(base64Key), c => c.charCodeAt(0)).buffer;
    } else {
        throw new Error("Invalid PEM key format. Expected PKCS#1 or PKCS#8.");
    }
}

async function signHash(messageHash, privateKeyPem) {
    const privateKeyBuffer = parsePemKeyprv(privateKeyPem);

    try {
        const privateKey = await crypto.subtle.importKey(
            "pkcs8",
            privateKeyBuffer,
            { name: "RSA-PSS", hash: "SHA-512" },
            false,
            ["sign"]
        );

        const encoder = new TextEncoder();
        const data = encoder.encode(messageHash);

        const signature = await crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            privateKey,
            data
        );

        return bytesToHex(new Uint8Array(signature));
    } catch (error) {
        ////console.error("Error in signHash:", error);
        throw error; // Rethrow to ensure caller handles the error
    }
}

// Build the message structure
async function buildMessageStructure(mimeMessage) {
    const filenames = [];
    const mimeString = mimeMessage;
    const filenameRegex = /filename(?:\*\d+\*|\s*=\s*)(?:utf-8''|")?(.*?)(?:;|$|")/gi;
    let match;
    let filenameParts = {};

    while ((match = filenameRegex.exec(mimeString)) !== null) {
        const filenamePart = match[1];
        const partIndex = match[0].includes('*') ? parseInt(match[0].match(/\*(\d+)/)?.[1] || 0) : -1;
        if (partIndex >= 0) {
            filenameParts[partIndex] = filenamePart;
        } else {
            filenames.push(decodeURIComponent(filenamePart.replace(/%([0-9A-F]{2})/gi, (m, p1) => String.fromCharCode(parseInt(p1, 16)))));
        }
    }

    if (Object.keys(filenameParts).length > 0) {
        const sortedParts = Object.keys(filenameParts)
            .sort((a, b) => a - b)
            .map(key => filenameParts[key]);
        const decodedFilename = decodeURIComponent(sortedParts.join('').replace(/%([0-9A-F]{2})/gi, (m, p1) => String.fromCharCode(parseInt(p1, 16))));
        filenames.push(decodedFilename);
    }

    //console.log("Extracted filenames:", filenames);
    const messageBuffer = new TextEncoder().encode(mimeString);

    return {
        files: filenames,
        timestamp: new Date().toISOString(),
        message: messageBuffer,
    };
}


async function buildSignaturePart(messageStructure, pubkeyId, privateKeyPem) {
    try {
        //console.log("Message Structure:", messageStructure);

        // Combine metadata and message into a single Uint8Array
        const encoder = new TextEncoder();
        const metadata = encoder.encode(
            JSON.stringify({
                files: messageStructure.files,
                timestamp: messageStructure.timestamp,
            })
        );
        const messageBuffer = messageStructure.message; // Uint8Array
        const combined = new Uint8Array(metadata.length + messageBuffer.length);
        combined.set(metadata, 0);
        combined.set(messageBuffer, metadata.length);

        // Use only native Web Crypto API
        const subtle = (typeof window !== "undefined" && window.crypto?.subtle);
        if (!subtle) {
            throw new Error("Web Crypto API not available in this environment. Please use a modern browser.");
        }

        // Hash the combined message
        const hashBuffer = await subtle.digest("SHA-512", combined);
        const messageHash = bytesToHex(new Uint8Array(hashBuffer));

        // Sign the hash using the provided private key
        const signature = await signHash(messageHash, privateKeyPem);

        // Return the signed part
        return {
            signature_timestamp: messageStructure.timestamp,
            public_key_id: pubkeyId,
            files: messageStructure.files,
            leading_octets_of_digest: getLeadingTwoOctets(messageHash),
            signature,
        };
    } catch (error) {
        //console.error("Error in buildSignaturePart:", error);
        throw error;
    }
}
// Build the blob for zipping
async function buildBlobForZip(messagePart, signaturePart) {
    return { signature_part: signaturePart, message_part: messagePart };
}


async function compressMessage(blob) {
    try {
        // Check if message contains compressed file types
        const isCompressedFile = blob.message_part.files?.some(file =>
            /\.(pptx|zip|jpg|png|gz|pdf)$/.test(file.toLowerCase())
        );

        // Prepare signature and message data
        const encoder = new TextEncoder();
        const signatureData = encoder.encode(JSON.stringify(blob.signature_part));
        const messageData = new Uint8Array(blob.message_part.message); // Ensure Uint8Array

        //console.log('Signature Data Size:', signatureData.length / 1024, 'KB');
        //console.log('Message Data Size:', messageData.length / 1024 / 1024, 'MB');

        // Create JSON structure
        const dataToCompress = {
            signature_part: blob.signature_part,
            message_part: Array.from(messageData) // Convert to array for JSON
        };

        const jsonString = JSON.stringify(dataToCompress);
        const jsonBytes = encoder.encode(jsonString);
        //console.log('JSON Bytes Size:', jsonBytes.length / 1024 / 1024, 'MB');

        // Skip compression for compressed files
        if (isCompressedFile) {
            //console.log('Skipping compression for compressed file types');
            return jsonBytes; // Return uncompressed JSON bytes
        }

        // Compress JSON bytes
        const compressedData = pako.deflate(jsonBytes, { level: 9 });
        //console.log('Compressed Data Size:', compressedData.length / 1024 / 1024, 'MB');
        return compressedData;
    } catch (error) {
        //console.error('Compression failed:', error);
        throw new Error(`Compression failed: ${error.message}`);
    }
}

// Encrypt using AES-GCM
async function encryptAesGcm(message) {
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        message // message is Uint8Array from compressMessage
    );

    // Export the AES key as raw binary
    const exportedKey = await crypto.subtle.exportKey("raw", key);

    return {
        ciphertext: new Uint8Array(ciphertext), // Keep as Uint8Array
        encryptionParams: {
            key: new Uint8Array(exportedKey), // Binary key
            iv: iv, // Binary IV
        },
    };
}

// Encrypt symmetric key with RSA
async function encryptSymmetricKeyWithRsa(data, publicKeyPem) {
    if (!publicKeyPem || typeof publicKeyPem !== 'string') {
        throw new Error('Public key is missing or invalid.');
    }
    if (
        !publicKeyPem.includes('-----BEGIN PUBLIC KEY-----') ||
        !publicKeyPem.includes('-----END PUBLIC KEY-----')
    ) {
        throw new Error('Invalid PEM format for public key.');
    }
    const publicKeyBuffer = parsePemKey(publicKeyPem);
    const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );

    // Serialize encryptionParams as JSON
    const paramsJson = JSON.stringify({
        key: bytesToHex(data.key), // Convert to hex for JSON
        iv: bytesToHex(data.iv)
    });
    const paramsBytes = new TextEncoder().encode(paramsJson);

    const encryptedData = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKey,
        paramsBytes
    );

    return new Uint8Array(encryptedData);
}

// Encrypted symmetric key
function encryptedSymmetricKey(keyId, encryptedKey) {
    return { key_id: keyId, encrypted_symmetric_key: encryptedKey };
}

// Construct the final form of the messageimport { Buffer } from 'buffer';

function constructFinalFormOfMessage(encryptedKey, ciphertext) {
    try {
        const keyIdBytes = new TextEncoder().encode(encryptedKey.key_id);
        const keyIdLengthValue = keyIdBytes.length;
        const keyBytes = encryptedKey.encrypted_symmetric_key;
        const keyLengthValue = keyBytes.length;

        // Validate lengths
        if (keyIdLengthValue < 1 || keyIdLengthValue > 1024) {
            throw new Error(`Invalid key_id length: ${keyIdLengthValue}`);
        }
        if (keyLengthValue < 1 || keyLengthValue > 4096) {
            throw new Error(`Invalid key length: ${keyLengthValue}`);
        }

        // Create buffers for lengths (big-endian)
        const keyIdLengthBuffer = new ArrayBuffer(4);
        new DataView(keyIdLengthBuffer).setUint32(0, keyIdLengthValue, false); // Big-endian

        const keyLengthBuffer = new ArrayBuffer(4);
        new DataView(keyLengthBuffer).setUint32(0, keyLengthValue, false); // Big-endian

        // Combine all parts
        const combined = new Uint8Array(
            4 + keyIdLengthValue + 4 + keyLengthValue + ciphertext.length
        );
        let offset = 0;
        combined.set(new Uint8Array(keyIdLengthBuffer), offset);
        offset += 4;
        combined.set(keyIdBytes, offset);
        offset += keyIdLengthValue;
        combined.set(new Uint8Array(keyLengthBuffer), offset);
        offset += 4;
        combined.set(keyBytes, offset);
        offset += keyLengthValue;
        combined.set(ciphertext, offset);

        // Debugging logs
        // //console.log('Key ID:', encryptedKey.key_id);
        // //console.log('Key ID Length:', keyIdLengthValue, 'Bytes:', bytesToHex(new Uint8Array(keyIdLengthBuffer)));
        // //console.log('Key Length:', keyLengthValue, 'Bytes:', bytesToHex(new Uint8Array(keyLengthBuffer)));
        // //console.log('Combined Array Size:', combined.length / 1024 / 1024, 'MB');
        // //console.log('First 16 Bytes (Hex):', bytesToHex(combined.slice(0, 16)));

        // Encode as Base64
        const base64 = Buffer.from(combined).toString('base64');
        //console.log('Base64 String Length:', base64.length);
        // //console.log('Base64 Preview:', base64.slice(0, 100) + '...');

        return base64;
    } catch (error) {
        //console.error('Error constructing final message:', error);
        throw new Error(`Failed to construct final message: ${error.message}`);
    }
}

async function signHashforLogin(messageHash, privateKeyPem) {
    const privateKeyBuffer = parsePemKeyprv(privateKeyPem);
    try {
        const privateKey = await crypto.subtle.importKey(
            "pkcs8", privateKeyBuffer, { name: "RSA-PSS", hash: "SHA-512" }, false, ["sign"]
        );
        const hashedMessage = await crypto.subtle.digest("SHA-512", messageHash);
        //console.log("Hashed message:", bytesToHex(new Uint8Array(hashedMessage)));
        try {
            const signature = await crypto.subtle.sign(
                { name: "RSA-PSS", saltLength: 32 }, privateKey, hashedMessage
            );
            //console.log("Signature:", signature);
            return bytesToHex(new Uint8Array(signature));
        } catch (error) {
            //console.error("Error during signing:", error);
        }
    } catch (error) {
        //console.error("Error importing key:", error);
    }
}

export {
    hexToBytes,
    bytesToHex,
    calculateHashMessage,
    getLeadingTwoOctets,
    signHash,
    buildMessageStructure,
    buildSignaturePart,
    buildBlobForZip,
    compressMessage,
    encryptAesGcm,
    encryptSymmetricKeyWithRsa,
    encryptedSymmetricKey,
    constructFinalFormOfMessage,
    signHashforLogin,
};