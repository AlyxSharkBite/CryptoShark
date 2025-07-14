# CryptoShark
Data Encryption Package for .NET 6

## Version History
**Version 1.0 - Initial Release**

* Password Based Encryption
* RSA Public/Private Key Encryption

**Version 2.1 - Update March 2022**

* .NET 6 Update
* Added ECC Encryption 

**Version 2.1.2 - Update April 2022**
* Added back the ability to work with Pkcs8 Encrypted Keys

**Version 3.0.0 - Update July 2025**
* .NET 9 Update
* Complete rewrite for easier use.
* Supports logging via ILogger interface
* Supports multiple forms of dependency injection

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

## Interfaces:

### ICryptoSharkCryptographyUtilities (Implimented by CryptoSharkCryptographyUtilities)
- Utility class for hashing, key creation & SecureString creation.

### Methods
- `ReadOnlySpan<byte> HashBytes(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm);`
    - Will compute the hash of the given data. 
    - See `HashAlgorithm.cs` for list of supported Hash Algorithms
- `string HashBytes(ReadOnlySpan<byte> data, Enums.HashAlgorithm hashAlgorithm, Enums.StringEncoding encoding);`
    - Will compute the hash of the given data.
    - See `HashAlgorithm.cs` for list of supported Hash Algorithms
    - See `StringEncoding.cs` for list of supported Text Encodings
- `ReadOnlySpan<byte> CreateAsymetricKey(IAsymmetricKeyParameter parameters);`
    - Creates an Asymetric Private Key in Pkcs8 Encrypted DER format
    - For Ecc Keys pass `EccKeyParameters` to method
    - For Rsa Keys pass `RsaKeyParameters` to method
- `ReadOnlySpan<byte> GetAsymetricPublicKey(ReadOnlySpan<byte> privateKey, SecureString password, CryptographyType cryptographyType);`
    - Gets the Asymetric Public Key from an Asymetric Private Key 
    - For Ecc Keys use `CryptographyType.EllipticalCurveCryptography`
    - For Ecc Keys use `CryptographyType.RivestShamirAdlemanCryptography`
- `SecureString StringToSecureString(string value);`
    - Creates a [SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0) from a string   

### Creation 
- Static Create Method
    - `ICryptoSharkCryptographyUtilities cryptographyUtilities = CryptoSharkCryptographyUtilities.Create(ilogger);`
- Factory Method
    - `ICryptoSharkCryptographyUtilities cryptographyUtilities = CryptoSharkFactory.CreateCryptographyUtilities(ilogger);`
- Public Constructor
    - `ICryptoSharkCryptographyUtilities cryptographyUtilities = new CryptoSharkCryptographyUtilities(ilogger)`

### ICryptoSharkSymmetricCryptography (Implimented by CryptoSharkPasswordCryptography)
- Symetric (Password based encryption) Encryption/Decryption

### Methods
- `ReadOnlyMemory<byte> Encrypt(IEncryptionRequest encryptionRequest);`
    - Encrypts data with password
    - Pass `SemetricEncryptionRequest` to method
- `ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, SecureString password);`
    - Decrypts previously encrypted data

### Creation 
- Static Create Method
    - `ICryptoSharkSymmetricCryptography symmetricCryptography = CryptoSharkPasswordCryptography.Create(ilogger);`
- Factory Method
    - `ICryptoSharkSymmetricCryptography symmetricCryptography = CryptoSharkFactory.CreateSymmetricCryptography(ilogger);`
- Public Constructor
    - `ICryptoSharkSymmetricCryptography symmetricCryptography = new CryptoSharkPasswordCryptography(ilogger)`

### ICryptoSharkCryptographyUtilities ECC Implimentation (Implimented by CryptoSharkEccCryptography)
- Asyemetric (Public/Private) ECC Encryption

### Methods
- `ReadOnlyMemory<byte> Encrypt(IAsymetricEncryptionRequest encryptionRequest);`
    - Encrypts data with ECC Public/Private Keys
    - Pass `AsymetricEncryptionRequest` to method
- `ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, ReadOnlySpan<byte> privateKey, SecureString password);`
    - Decrypts previously encrypted data

### Creation 
- Static Create Method
    - `ICryptoSharkAsymmetricCryptography asymmetricCryptography = CryptoSharkEccCryptography.Create(ilogger);`
- Factory Method
    - `ICryptoSharkAsymmetricCryptography asymmetricCryptography = CryptoSharkFactory.CreateAsymmetricCryptography(ilogger, CryptographyType.EllipticalCurveCryptography);`
- Public Constructor
    - `ICryptoSharkAsymmetricCryptography asymmetricCryptography = new CryptoSharkEccCryptography(ilogger)`

### ICryptoSharkCryptographyUtilities RSA Implimentation (Implimented by CryptoSharkRsaCryptography)
- Asyemetric (Public/Private) RSA Encryption

### Methods
- `ReadOnlyMemory<byte> Encrypt(IAsymetricEncryptionRequest encryptionRequest);`
    - Encrypts data with RSA Public/Private Keys
    - Pass `AsymetricEncryptionRequest` to method
- `ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, ReadOnlySpan<byte> privateKey, SecureString password);`
    - Decrypts previously encrypted data

### Creation 
- Static Create Method
    - `ICryptoSharkAsymmetricCryptography asymmetricCryptography = CryptoSharkRsaCryptography.Create(ilogger);`
- Factory Method
    - `ICryptoSharkAsymmetricCryptography asymmetricCryptography = CryptoSharkFactory.CreateAsymmetricCryptography(ilogger, CryptographyType.RivestShamirAdlemanCryptography);`
- Public Constructor
    - `ICryptoSharkAsymmetricCryptography asymmetricCryptography = new CryptoSharkRsaCryptography(ilogger)`
    
## Support Classes:

### EccKeyParameters
- Used to create ECC Private Key

### Creation 
- `IAsymmetricKeyParameter parameter = new EccKeyParameters(password, ECCurve.NamedCurves.nistP256);`

### RsaKeyParameters
- Used to create RSA Private Key

### Creation 
- `IAsymmetricKeyParameter parameter = new RsaKeyParameters(password, RsaKeySize.KeySize2048);`

### AsymetricEncryptionRequest
- Request to Encrypt with Public/Private Key

### Creation 
    - `IAsymetricEncryptionRequest request = AsymetricEncryptionRequest.CreateRequest(
                publicKey: publicKey,                                   // Public Key to use      
                privateKey: privateKey,                                 // Private Key to use
                clearData: dataToEncrypt,                               // Data to encrypt
                password: password,                                     // Private Key Password
                algorithm: CryptoShark.Enums.EncryptionAlgorithm.Aes    // Encryption Algorithm to use
            );`

### SemetricEncryptionRequest
- Request to Encrypt with Password

### Creation 
    - `IEncryptionRequest request = SemetricEncryptionRequest.CreateRequest(                
                clearData: dataToEncrypt,                               // Data to encrypt
                password: password,                                     // Password to use
                algorithm: CryptoShark.Enums.EncryptionAlgorithm.Aes    // Encryption Algorithm to use
            );`