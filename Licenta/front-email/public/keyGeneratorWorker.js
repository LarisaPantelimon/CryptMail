/* eslint-disable no-restricted-globals */
//console.log("Worker initialized");

// Polifil pentru window ?i window.crypto
self.window = self;
self.window.crypto = self.crypto;

self.onmessage = async () => {
    //console.log("Worker received message");

    try {
        //console.log("Loading node-forge...");
        self.importScripts('/forge.min.js'); // forge.min.js trebuie sa existe �n public/
        //console.log("Forge object:", self.forge);
        const forge = self.forge;

        if (!forge) {
            throw new Error("Forge not available in worker context");
        }

        //console.log("Node-forge loaded, generating RSA key pair...");
        const keyPair = forge.pki.rsa.generateKeyPair({ bits: 4096 }); 
        const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);
        const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
        //console.log("RSA key pair generated successfully");
        self.postMessage({ privateKeyPem, publicKeyPem });

    } catch (error) {
        //console.error("Worker error:", error);
        self.postMessage({ error: error.message });
    }
};