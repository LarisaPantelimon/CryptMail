import forge from 'node-forge';
import bcrypt from 'bcryptjs';
import {toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const generateRsaKeyPair = () => {
        return new Promise((resolve, reject) => {
            try {
                const keyPair = forge.pki.rsa.generateKeyPair(4096);
    
                resolve({
                    privateKeyPem: forge.pki.privateKeyToPem(keyPair.privateKey),
                    publicKeyPem: forge.pki.publicKeyToPem(keyPair.publicKey)
                });
            } catch (error) {
                reject('Error generating RSA key pair: ' + error.message);
            }
        });
    };

const generateRsaKeyPairWorker = () => {
  return new Promise((resolve, reject) => {
    //console.log("Starting Web Worker for RSA key generation...");
    const timeout = setTimeout(() => {
      reject(new Error("RSA key generation timed out after 60 seconds"));
    }, 120000);

    const worker = new Worker('/keyGeneratorWorker.js'); // Calea statica
    worker.onmessage = (event) => {
      clearTimeout(timeout);
      //console.log("Received message from worker:", event.data);
      if (event.data.error) {
        reject(new Error('Error generating RSA key pair: ' + event.data.error));
      } else {
        resolve({
          privateKeyPem: event.data.privateKeyPem,
          publicKeyPem: event.data.publicKeyPem,
        });
      }
      worker.terminate();
    };
    worker.onerror = (error) => {
      clearTimeout(timeout);
      //console.error("Worker error:", error);
      reject(new Error('Worker error: ' + (error.message || 'Unknown error')));
      worker.terminate();
    };
    //console.log("Posting message to worker...");
    worker.postMessage({});
  });
};
const encryptWithPassword = (privateKeyPem, password) => {
            try {
                const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    
                const encryptedPrivateKey = forge.pki.encryptRsaPrivateKey(privateKey, password, {
                    algorithm: 'aes256',
                    count: 2048,
                    saltSize: 16,
                    prfAlgorithm: 'sha256',
                    legacy: false  
                });            
                
                return encryptedPrivateKey;
            } catch (error) {
                //console.error("Encryption error:", error);
                throw new Error("Failed to encrypt private key. Please check your input and try again.");
            }
};

const decryptWithPassword = (encryptedPrivateKey, password) => {
        try {
            ////console.log("Decrypting private key with the old password...",password);

            if (typeof encryptedPrivateKey !== 'string' || encryptedPrivateKey.length === 0) {
                //console.log("Encrypted private key is not in a valid format.");
            }
            const privateKey = forge.pki.decryptRsaPrivateKey(encryptedPrivateKey, password);            

            if (!privateKey) {
                //console.log("Decryption failed. Incorrect password or corrupted data.");
            }

            const decryptedPrivateKeyPem = forge.pki.privateKeyToPem(privateKey);
            return decryptedPrivateKeyPem;
        } catch (error) {
            //console.log("Decryption error:", error);
            // throw new Error("Failed to decrypt private key. Please check your password and try again.");
        }
};

async function hashPassword(password) {
          const salt = await bcrypt.genSalt(10); 
          return await bcrypt.hash(password, salt);
}

const encryptWithPasswordAsync = async (privateKeyPem, password) => {
    try {
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

        const encryptedPrivateKey = forge.pki.encryptRsaPrivateKey(privateKey, password, {
            algorithm: 'aes256',
            count: 2048,
            saltSize: 16,
            prfAlgorithm: 'sha256',
            legacy: false  
        });            
        
        return encryptedPrivateKey;
    } catch (error) {
        toast.error("Encryption error:", error);
        // throw new Error("Failed to encrypt private key. Please check your input and try again.");
    }
};

export{
    generateRsaKeyPair,
    encryptWithPassword,
    decryptWithPassword,
    hashPassword,
    encryptWithPasswordAsync,
    generateRsaKeyPairWorker,
}