# CryptoShark
## Cross Platform Data Encryption Package for .NET 9

## Version History
**Version 1.0 - Initial Release**
* Password Based Encryption
* RSA Public/Private Key Encryption

**Version 2.1**
* .NET 6 Update
* Added ECC Encryption 

**Version 2.1.2**
* Added back the ability to work with Pkcs8 Encrypted Keys

**Version 3.0.0**
* .NET 9 Update
* Complete rewrite for easier use.
* Supports logging via ILogger interface
* Supports multiple forms of dependency injection

**Version 3.1.0**
* Replaced all .Net Ecc Cryptography Next Generation (CNG) with BouncyCastle code

**Version 3.2.0**
* Updated RSA Keys to use Encrypted PEM format same as ECC Keys
* Replaced all .Net Rsa Cryptography Next Generation (CNG) with BouncyCastle code

**Version 3.5.0**
* Added ability to default many options via ICryptoSharkConfiguration
* Internal code updates to make future enhaemnts easier
* Exposed all the internal parts allowing supplying the desired options
    * Hash Alorythm for verifying data integrity can now be chosen
    * RSA Padding for RSA Encryption can now be set with stanard strings 
        * Example: 'OAEPWithSHA-256AndMGF1Padding'
 * Performance Enhancements
 * Added option to compress data before encryption useing [Huffman Coding](https://en.wikipedia.org/wiki/Huffman_coding)
    * Huffman Coding is very fast even over large data and will only slightly reduce speed
    * Benchmark on 1Mb Data on Intel Core Ultra 285 
    ```
    | Method                | Mean     | Error   | StdDev   |
    |---------------------- |---------:|--------:|---------:|
    | EncryptNoCompresstion | 108.5 ms | 8.41 ms | 24.79 ms |
    | EncryptCompresstion   | 104.1 ms | 7.72 ms | 22.63 ms |
    ```

 **Version 3.5.1**
 * Minor Security Enhancements 
    * Password is no supplyed as a char[] not string and is cleard once converted to SecureString
  
## About
Code written on macOS & Windows 11

The concept is to have a simple and powerful took for Data Encryption with cross platform support (Windows, macOS, Linux).  

[BouncyCastle](https://www.bouncycastle.org) is the core of the Encryption and Decryption. 

Encryption is done with a 256 Bit Key using Galois/Counter Mode (GCM).  The following encryption algorithms are supported:

* [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher))
* [CAST6 / CAST-256](https://en.wikipedia.org/wiki/CAST-256)
* [RC6](https://en.wikipedia.org/wiki/RC6)
* [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher))
* [TwoFish](https://en.wikipedia.org/wiki/Twofish)
           
## Using Concepts
Designed to fit your workflow, all public classes have interfaces for easy dependency injection

* Factory for Creation
* Static Create Methods
* Traditional Constructiors

## Keys
* As of 3.1 Ecc Keys are in the Encrypted PEM Format. Yu can use ones created elsewhere if you want even, simply read the PEM file into a byte array and pass it in as the Ecc Private Key along with the passwor. So this gives you the flexibity to use ones created elsewhere, i.e. open ssl.
* As of 3.2 Rsa Keys are stored the same way.

### Example ECC PEM Key
```
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: BF-OFB,8603D84AEEA59E80

obqDJP9JA/Dfv5rwlgxyk6+aCyGPHRQ0xHKog5/fcULQbHQhFfe9p+LzXskZEehr
K5hGjVOe7lb0vnViE2v36KUdAXvE0yP9Jz0tx2poUKIPB1Neg8w1rxJJWBeBok5s
1nE0oaZLfjowykgLef1QmAOCcMSf3NWH8sBh4JE39ja2yLb35OD6MT0P7lZCcAes
kBWyzyhrWTGWcJUqYtEWcz98PmNDFUFSld2hQFsGX5koYrAQLGCFp60sZ0cRVkRS
kC4H9sdC6+zGPP1McUjOlhA40R5uUMOL09PMOa0/P0+e1QkHIajbcEXqbr3XjSSW
KJOqYZd48HG1Fc/fqpLYhUjye1TSG4gY/XevJFkdpuJqgYYZbcJZL/wqSmva+d0R
xYDWOUHIuvSa3vJo1uH1EbHAONaLnO0AQUM3fHsLS8JiSJpUDVMuBtnueW7ohsRR
HSJDlSq5JVJZ44nRKBYdfKGuyoqKOGHMfyHOGbDUOBLNSmdBNb9rNEAV+UFB8Ex8
XkUqRQJQfo6KvmLYQJ1whegrVxA5Eu3GRW1wfMF4/+PewyfRp9JqtiFawEXpaM0w
gKp8tdUKx2NMcvgDbpFgn1XenVuDN7pyZtsOWx5QDgphoL04hx27QGp4DbflshgA
EeFw3nIc4Vq0OQozcUuanLgzeUT7e3hi2eW0Vm/n
-----END EC PRIVATE KEY-----
```

### Example RSA PEM Key
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: BF-OFB,45DAED7D531B4775

mUsWdDxW3CoSAvat5ymXZNne0ZmhxRzXqRTwCtzgJLAJzTi+NY+VucVu2LoRgHX1
Fmtp8EzRXzzPvxBanjSkwbdz36j97IUk+ZNxBCwFabR6P8BbFCCu36ZLlV41OT+C
8UHy9/v41DVUOi5qYhqxzITEBiB0QC+pAuW+vo++ixcWMQzRFaFo8QTcnVaK2c4W
hIIMbdaMaWh0qd9ElqSGA02YS9gcuE4DJF/aCq1A5hnV7BjoROYcqz45nBnqUa9m
H4ygcpUQWAfOeI9kB9lrUlkb3KqZxxMQxANsDs/USxC4gELNZKsMT7ufK8gG2j+n
/Tq2Ovldz6AupHfy0f3UEKUJsOgbKCoVL6WiW0Lzr9Nu9kYj/aHLuw7m343da7NB
KX9pftNqikwaIe91HnpUyNXji7lENcOwif2EXT8uRBTJJ+Ea+0JJwna5x8vZGrcx
EMlRbbvGzmQA+vr9tpaWKT/Qak86OGRubusWWjDxrQX/yPgciBJfMgI1ezVPR4vj
9Am4rd25k4jh/K8hSRcFkKdWO/81GTaQtVVpv2hjBaaoZdHxPcWrHoNRR2ktq5XS
7CyXPJIg1IsZImXgvBTtI/iiOPeo+TIG/2ich5KlGlIilqdDwg+R67xasn2Zcsfr
3eip9Yx+B8WkcDe6l900bRQLpuQ/7C5Kmdlw5m5GbDxsQUj8SiScc2tBtai1V63L
VfeIOQ41hD/WJehRBGMRzspUwNhs0FIO+QjHJW1ikWW8dJryKF/YpWr+1sTot3ri
6yaSgvKZzsVaVPrGIxhTH8FuNvlODXgnIOfNVS0hMDE=
-----END RSA PRIVATE KEY-----
```

## Example Use: 

### Create The Configuration
*Create a new CryptoSharkConfiguration (Or derive your own from ICryptoSharkConfiguration)*
* Example:
 `ryptoSharkConfiguration configuration = new CryptoSharkConfiguration();`

 ### Create the Factory
 `var factory = CryptoSharkFactory.CreateCryptoSharkFactory(ilogger, configuration);`

 ### Create a ECC Cryptograpy Provider
 `var ecc = factory.CreateAsymmetricCryptography(CryptographyType.EllipticalCurveCryptography);`

  ### Create a Rsa Cryptograpy Provider
 `var rsa = factory.CreateAsymmetricCryptography(CryptographyType.RivestShamirAdlemanCryptography);`

### Create a Password Based Cryptograpy Provider
 `var pbe = factory.CreateSymmetricCryptography();`

### Create Cryptographic Utility Provider 
 `var utilities = factory.CreateCryptographyUtilities();`

 ## Encryption & Decription are handeled via requests, see
 * AsymetricEncryptionRequest
 * SemetricEncryptionRequest

 ## Results are returned as ReadOnlyMemory<byte> consisting of serialized records 
