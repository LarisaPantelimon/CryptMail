import SEAL from 'node-seal';

async function encryptFullStringWithSEAL(publicKeyBase64, str) {
    const seal = await SEAL();
    // Hardcoded params
    const polyModulusDegree = 4096;
    const plainModulusBitSize = 20;

    const parms = seal.EncryptionParameters(seal.SchemeType.bfv);
    
    parms.setPolyModulusDegree(polyModulusDegree);
    parms.setCoeffModulus(seal.CoeffModulus.BFVDefault(polyModulusDegree));
    parms.setPlainModulus(seal.PlainModulus.Batching(polyModulusDegree, plainModulusBitSize));
  
    const context = seal.Context(parms);
    //console.log("Context created:", context);
    const publicKey = seal.PublicKey();
    publicKey.load(context, publicKeyBase64);
  
    const encryptor = seal.Encryptor(context, publicKey);
    const batchEncoder = seal.BatchEncoder(context); // For batch encoding
  
    // Convert string to Uint8Array
    const strBytes = new TextEncoder().encode(str);
    //console.log("String bytes:", strBytes);

    // Convert Uint8Array to Int32Array (padded with zeros)
    const intArray = new Int32Array(polyModulusDegree).fill(0);
    strBytes.forEach((byte, index) => {
        intArray[index] = byte; // Copy bytes into Int32Array
    });

    //console.log("Int32Array for encoding:", intArray);
    const plain = batchEncoder.encode(intArray);
  
    const ciphertext = seal.CipherText();
    encryptor.encrypt(plain, ciphertext);
  
    return btoa(ciphertext.save()); // Convert to Base64 for easier transport/storage
}

export{
    encryptFullStringWithSEAL,
}