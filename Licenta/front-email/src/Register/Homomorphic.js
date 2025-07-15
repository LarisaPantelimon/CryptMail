import CryptoJS from 'crypto-js'; // For AES encryption
import JSBI from 'jsbi';
const forge = require('node-forge');

/**
 * Generates a cryptographically secure random BigInt in the range [1, max-1].
 * @param {JSBI} max - The upper bound (e.g., n_web or n_app).
 * @returns {JSBI} A random BigInt x where 1 <= x < max.
 */

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function generateRandomBigInt(max) {
    const maxBig = JSBI.BigInt(max);
    if (JSBI.lessThanOrEqual(maxBig, JSBI.BigInt(1))) {
        throw new Error('Max must be greater than 1');
    }

    const byteLength = Math.ceil(maxBig.toString(16).length / 2);
    let random;
    do {
        const bytes = new Uint8Array(byteLength);
        window.crypto.getRandomValues(bytes); // Browser-native crypto
        const hex = bytesToHex(bytes);
        random = JSBI.BigInt('0x' + hex);
    } while (JSBI.GE(random, maxBig));

    if (JSBI.equal(random, JSBI.BigInt(0))) {
        random = JSBI.BigInt(1);
    }

    return random;
}

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

function parseRSAPublicKey(pem) {
    const derBytes = parsePemKey(pem);
    const der = forge.util.createBuffer(derBytes);
    const publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(der));
    return {
        n: publicKey.n.toString(), // 4096-bit
        e: publicKey.e.toString()  // Typically 65537
    };
}

function parseRSAPrivateKey(pem) {
    const derBytes = parsePemKey(pem);
    const der = forge.util.createBuffer(derBytes);
    const privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(der));
    return {
        n: privateKey.n.toString(), // 4096-bit modulus
        d: privateKey.d.toString()  // Private exponent
    };
}


function encryptChallenges(webPublicKey, appPublicKey, email) {
    const { n: n_web, e: e_web } = parseRSAPublicKey(webPublicKey);
    const { n: n_app } = parseRSAPublicKey(appPublicKey);
    const nWebBig = JSBI.BigInt(n_web);
    const eWebBig = JSBI.BigInt(e_web);
    const nAppBig = JSBI.BigInt(n_app);

    // Validate inputs
    if (!n_web || !e_web || !n_app) {
        throw new Error('Invalid public key parameters');
    }

    const m = generateRandomBigInt(nWebBig);
    const encM = modPow(m, eWebBig, nWebBig);
    const hashInput = encM.toString(16) + n_web + email;
    const hash = CryptoJS.SHA256(hashInput);
    const hashHex = hash.toString(CryptoJS.enc.Hex);

    // Compute c = SHA256(...) mod n_app
    const hashBig = JSBI.BigInt('0x' + hashHex);
    const c = JSBI.remainder(hashBig, nAppBig);

    //console.log(`encM=${encM.toString(16)}, c=${c.toString(16)}, hashInput=${hashInput}`);
    return {
        encM: encM.toString(16),
        c: c.toString(16),
        m
    };
}


function modPow(base, exponent, modulus) {
    base = JSBI.BigInt(base);
    exponent = JSBI.BigInt(exponent);
    modulus = JSBI.BigInt(modulus);
    let result = JSBI.BigInt(1);
    base = JSBI.remainder(base, modulus);
    while (JSBI.greaterThan(exponent, JSBI.BigInt(0))) {
        if (JSBI.equal(JSBI.remainder(exponent, JSBI.BigInt(2)), JSBI.BigInt(1))) {
            result = JSBI.remainder(JSBI.multiply(result, base), modulus);
        }
        base = JSBI.remainder(JSBI.multiply(base, base), modulus);
        exponent = JSBI.divide(exponent, JSBI.BigInt(2));
    }
    return result;
}



function verifyZKP(encMC, s, c, m, webPrivateKey, appPublicKey) {
    const { n: n_web, d: d_web } = parseRSAPrivateKey(webPrivateKey);
    const { e: e_app, n: n_app } = parseRSAPublicKey(appPublicKey);
    const nWebBig = JSBI.BigInt(n_web);
    const dWebBig = JSBI.BigInt(d_web);
    const eAppBig = JSBI.BigInt(e_app);
    const nAppBig = JSBI.BigInt(n_app);
    const encMCBig = JSBI.BigInt('0x' + encMC);
    const sBig = JSBI.BigInt('0x' + s);
    const mBig = JSBI.BigInt(m.toString());
    const cBig = JSBI.BigInt('0x' + c);

    // Decrypt Enc(m * c) to get m^c
    const decrypted = modPow(encMCBig, dWebBig, nWebBig);
    const expected = modPow(mBig, cBig, nWebBig);
    const homoVerified = JSBI.equal(decrypted, expected);

    // Verify RSA proof: s^e_app == c mod n_app
    const proofLeft = modPow(sBig, eAppBig, nAppBig);
    const proofRight = cBig;
    const proofVerified = JSBI.equal(proofLeft, proofRight);

    const verified = homoVerified && proofVerified;
    //console.log(`ZKP verified: homo=${homoVerified}, proof=${proofVerified}`);
    return verified;
}

async function handleZKPResponse(response, m, c, webPrivateKey, appPublicKey) {
    try {
        //console.log(response);
        const {finalZPK,success } = response;
        if (!success || !finalZPK || !finalZPK[0] || !finalZPK[1]) {
            throw new Error('ZKP response missing data');
        }
        const encMC=finalZPK[0];
        const s=finalZPK[1];
        //console.log(encMC,s);
        return verifyZKP(encMC, s, c, m, webPrivateKey, appPublicKey);
    } catch (e) {
        //console.error('ZKP error:', e);
        return false;
    }
}

export {
    parsePemKey,
    //generateZKChallenges,
    encryptChallenges,
    handleZKPResponse
};