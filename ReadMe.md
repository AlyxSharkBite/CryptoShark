# CryptoShark
Data Encryption Package for .Net Core 3.1

## Version History
**Version 1.0 - Initial Release**

* Password Based Encryption
* RSA Public/Private Key Encryption

## About
Code written on macOS Catalina (10.15)

The concept is to have a simple and powerful took for Data Encryption with cross platform support (Windows, macOS, Linux).  

[BouncyCastle](https://www.bouncycastle.org) is the core of the Encryption and Decryption removing any concerns of export restrictions. 

Encryption is done with a 256 Bit Key using Galois/Counter Mode (GCM).  The following encryption algorithms are supported:

* [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher))
* [CAST6 / CAST-256](https://en.wikipedia.org/wiki/CAST-256)
* [RC6](https://en.wikipedia.org/wiki/RC6)
* [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher))
* [TwoFish](https://en.wikipedia.org/wiki/Twofish)
             
## Usage
`string password = "Abc123";
byte[] data = new byte[4096];`

### Password Based Encryption

            // Encrypt
            CryptoShark.PBEncryption encryption = new CryptoShark.PBEncryption();

            var encrypted = encryption.Encrypt(data, password, CrytoShark.EncryptionAlgorithm.TwoFish);

            // Decrypt
            var decrypted = encryption.Decrypt(encrypted.EncryptedData,
                            password,
                            encrypted.Algorithm,
                            encrypted.GcmNonce,
                            encrypted.PbkdfSalt,
                            encrypted.Sha384Hmac,
                            encrypted.Itterations);


### RSA Encryption
*This is the most simplistic example the RSAUtilites can also encrypt the RSA Private keys as well as other functions.  See documentation.*


            // Create the RSA Encryption Object
            CryptoShark.RsaEncryption encryption = new CryptoShark.RsaEncryption();

            // Create a Couple RSA Keys
            var key1 = encryption.RSAUtilities.CreateRsaKey(2048);
            var key2 = encryption.RSAUtilities.CreateRsaKey(2048);

            // Get the Public Keys
            var key1Pub = encryption.RSAUtilities.GetRsaPublicKey(key1);
            var key2Pub = encryption.RSAUtilities.GetRsaPublicKey(key2);

            // Encrypt
            var encrypted = encryption.Encrypt(data, key1Pub, key2, CrytoShark.EncryptionAlgorithm.TwoFish);

            // Decrypt
            var decrypted = encryption.Decrypt(encrypted.EncryptedData,
                key2Pub,
                key1,
                encrypted.Algorithm,
                encrypted.GcmNonce,
                encrypted.RSASignature,
                encrypted.EncryptionKey);


### Hashing
*CryptoShark has a Hashing engine supporting most common Hash Algorithms*
The CryptoShark.HashUtilites has two static methods for hashing data.
One returns a string in the specified encoding (Hex, Base64 or Bas64Url)
The other a ReadOnlySpan<byte> 

                
## Future Development        
* Move to .Net 5 once it is released in November 2020.  
* Elliptical Curve Cryptography
* Add support for optional Data Compression before Encryption        
                
                