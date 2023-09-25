import nodeRSA from 'node-rsa';

/**
 * return the decrypted Data (RSA OAEP Encryption)
 * @param {string} RSAPrivateKey 
 * @param {string} EncrypteDataBuffer
 * @returns {string} Data decrypted data
 */
var RSA_OAEP_Decrypt = function(RSAPrivateKey, encryptedData){
    // ----- Setting RSA OAEP Configuration [ start ] -----
    let RSAPrivate = new nodeRSA(RSAPrivateKey);
    RSAPrivate.setOptions({
        environment: 'browser',
        encryptionScheme: {
            scheme: 'pkcs1_oaep',
            hash: 'sha256'
        }
    });
    // ----- Setting RSA OAEP Configuration [ end ] -----
  
    let result = RSAPrivate.decrypt(encryptedData);
    return result;
};

/**
 * Decrypts the given base64 encrypted challenge using the private key
 * @param {string} challenge the base64 encoded challenge obtained from login
 * @returns unencrypted challenge
 */
export function decrypt(challenge) {
    const decrypted = RSA_OAEP_Decrypt(process.env.RSA_PRIVATE_KEY, challenge)
    return decrypted.toString("utf8")
}