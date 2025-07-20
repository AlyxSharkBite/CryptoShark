using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Record;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;

[assembly: InternalsVisibleTo("CryptoSharkTests")]
namespace CryptoShark
{
    /// <summary>
    /// ECC Encryption
    /// </summary>
    internal sealed class EccEncryption
    {
        private const int KEY_SIZE = 256;
        private readonly ILogger _logger;
        private readonly CryptoSharkUtilities _cryptoSharkUtilities;
        private readonly SecureStringUtilities _secureStringUtilities;
        private readonly AsymmetricCipherUtilities _asymmetricCipherUtilities;
        private readonly SecureRandom _secureRandom;        

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger">ILogger</param>
        public EccEncryption(ILogger logger)
        {
            _logger = logger;           
            _cryptoSharkUtilities = new CryptoSharkUtilities(logger);
            _secureStringUtilities = new SecureStringUtilities();
            _asymmetricCipherUtilities = new AsymmetricCipherUtilities();
            _secureRandom = new SecureRandom();
        }
       
        public Result<EccCryptographyRecord, Exception> Encrypt(
            ReadOnlyMemory<byte> clearData,
            ReadOnlyMemory<byte> eccPublicKey,
            ReadOnlyMemory<byte> eccPrivateKey,
            EncryptionAlgorithm encryptionAlgorithm,
            Enums.HashAlgorithm hashAlgorithm,
            SecureString password,
            bool? compress)
        {
            try
            {
                var engine = new EncryptionEngine(encryptionAlgorithm);                

                // Generate Data
                var nonceResult = GenerateSalt();
                if (nonceResult.IsFailure)
                    return Result.Failure<EccCryptographyRecord, Exception>(nonceResult.Error);

                var keyResult = GenerateKey(eccPrivateKey, eccPublicKey, nonceResult.Value, password);
                if(keyResult.IsFailure)
                    return Result.Failure<EccCryptographyRecord, Exception>(keyResult.Error);

                var hashResult = ComputeHash(clearData, hashAlgorithm);
                if (hashResult.IsFailure)
                    return Result.Failure<EccCryptographyRecord, Exception>(hashResult.Error);

                // Sign Hash
                var signedHashResult = SignHash(hashResult.Value, eccPrivateKey, password);
                if (signedHashResult.IsFailure)
                    return Result.Failure<EccCryptographyRecord, Exception>(signedHashResult.Error);

                // Encrypt
                var encrypted = engine.Encrypt(clearData, keyResult.Value, nonceResult.Value, compress ?? false);

                // Build the response
                return new EccCryptographyRecord
                {
                    EncryptionAlgorithm = encryptionAlgorithm,
                    PublicKey = eccPublicKey.ToArray(),
                    Signature = signedHashResult.Value.ToArray(),
                    EncryptedData = encrypted.ToArray(),
                    Nonce = nonceResult.Value.ToArray(),
                    HashAlgorithm = hashAlgorithm
                };                
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:Encrypt {message}", ex.Message);
                return Result.Failure<EccCryptographyRecord, Exception>(ex);
            }
        }


        /// <summary>
        ///     Decrypts Previously Encrypted Data
        /// </summary>
        /// <param name="encryptedData">Encrypted Data</param>
        /// <param name="eccPublicKey">Publi Key to Verify Signature WITH</param>
        /// <param name="eccPrivateKey">Private Key to Decrypt WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="nonce">Nonce Token</param>
        /// <param name="eccSignature">Signature</param>     
        /// <param name="password">Password for Private Key</param> 
        /// <returns></returns>
        public Result<ReadOnlyMemory<byte>, Exception> Decrypt(ReadOnlyMemory<byte> encryptedData, ReadOnlyMemory<byte> eccPublicKey, 
            ReadOnlyMemory<byte> eccPrivateKey, EncryptionAlgorithm encryptionAlgorithm, Enums.HashAlgorithm hashAlgorithm, 
            ReadOnlyMemory<byte> nonce,ReadOnlyMemory<byte> eccSignature, SecureString password)
        {
            try
            {
                // Create Engine
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Derive the Key
                var keyResult = GenerateKey(eccPrivateKey, eccPublicKey, nonce, password);
                if (keyResult.IsFailure)
                    return Result.Failure<ReadOnlyMemory<byte>, Exception>(keyResult.Error);

                // Decrypt
                var clearData = engine.Decrypt(encryptedData, keyResult.Value, nonce);

                // Compute Hash
                var hashResult = ComputeHash(clearData, hashAlgorithm);
                if (hashResult.IsFailure)
                    return Result.Failure<ReadOnlyMemory<byte>, Exception>(hashResult.Error);

                // Verify Hash
                var verifyResult = VerifyHash(hashResult.Value, eccSignature, eccPublicKey);
                if (verifyResult.IsFailure)
                    return Result.Failure<ReadOnlyMemory<byte>, Exception>(verifyResult.Error);
                if (verifyResult.Value == false)
                    return Result.Failure<ReadOnlyMemory<byte>, Exception>(new CryptographicException("Invalid Signature"));

                return clearData;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:Decrypt {message}", ex.Message);
                return Result.Failure<ReadOnlyMemory<byte>, Exception>(ex);
            }
        }

        #region PrivateMethods
        private Result<bool, Exception> VerifyHash(ReadOnlyMemory<byte> hash, ReadOnlyMemory<byte> signature, 
            ReadOnlyMemory<byte> eccPublicKey)
        {
            try
            {
                var publicKey = _asymmetricCipherUtilities.ReadPublicKey(eccPublicKey.ToArray());
                var dsaSignature = ECDsaSignature.FromByteArray(signature);

                var signer = new ECDsaSigner();
                signer.Init(false, publicKey);

                return signer.VerifySignature(hash.ToArray(), dsaSignature.r, dsaSignature.s);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:VerifyHash {message}", ex.Message);
                return Result.Failure<bool, Exception>(ex);
            }
        }

        private Result<ReadOnlyMemory<byte>, Exception> ComputeHash(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            return _cryptoSharkUtilities.Hash(data, hashAlgorithm);
        }

        private Result<ReadOnlyMemory<byte>, Exception> SignHash(ReadOnlyMemory<byte> hash, ReadOnlyMemory<byte> eccPrivateKey, 
            SecureString password)
        {   
            try
            {
                var privateKey = _asymmetricCipherUtilities.ReadPrivateKey(eccPrivateKey.ToArray(), password);

                var signer = new ECDsaSigner();
                signer.Init(true, privateKey);
                var signature = signer.GenerateSignature(hash.ToArray());

                var dsaSignature = new ECDsaSignature(signature[0], signature[1]);

                return dsaSignature.ToArray();               
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:SignHash {message}", ex.Message);
                return Result.Failure<ReadOnlyMemory<byte>, Exception>(ex);
            }
        }

        private Result<ReadOnlyMemory<byte>, Exception> GenerateSalt(int size = 16)
        {
            try
            {
                var salt = new byte[size];                
                _secureRandom.NextBytes(salt);

                return new ReadOnlyMemory<byte>(salt);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:GenerateSalt {message}", ex.Message);
                return Result.Failure<ReadOnlyMemory<byte>, Exception>(ex);
            }
        }

        private Result<ReadOnlyMemory<byte>, Exception> GenerateKey(ReadOnlyMemory<byte> eccPrivateKey, ReadOnlyMemory<byte> eccPublicKey,
            ReadOnlyMemory<byte> salt, SecureString password)
        {            
            try
            {
                ReadOnlyMemory<byte> derivedKey = new byte[256 / 8];

                var privateKey = _asymmetricCipherUtilities.ReadPrivateKey(eccPrivateKey.ToArray(), password);
                var publicKey = _asymmetricCipherUtilities.ReadPublicKey(eccPublicKey.ToArray());

                var exch = new Org.BouncyCastle.Crypto.Agreement.ECDHBasicAgreement();
                exch.Init(privateKey);
                var seed = exch.CalculateAgreement(publicKey).ToByteArray();

                var hkdf = new HkdfBytesGenerator(new Sha3Digest());
                hkdf.Init(new HkdfParameters(seed, salt.ToArray(), null));                
                hkdf.GenerateBytes(derivedKey.ToArray(), 0, derivedKey.Length);

                return derivedKey;

            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:GenerateKey {message}", ex.Message);
                return Result.Failure<ReadOnlyMemory<byte>, Exception>(ex);
            }
        }       

        #endregion
    }
}
