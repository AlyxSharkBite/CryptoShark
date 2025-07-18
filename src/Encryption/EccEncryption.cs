﻿using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Record;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

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
       
        public Result<EccCryptographyRecord, Exception> Encrypt(ReadOnlyMemory<byte> clearData, ReadOnlySpan<byte> eccPublicKey,
            ReadOnlySpan<byte> eccPrivateKey, EncryptionAlgorithm encryptionAlgorithm, Enums.HashAlgorithm hashAlgorithm,
            SecureString password)
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
                var encrypted = engine.Encrypt(clearData, keyResult.Value, nonceResult.Value);

                // Build the response
                return new EccCryptographyRecord
                {
                    EncryptionAlgorithm = encryptionAlgorithm,
                    PublicKey = eccPublicKey.ToArray(),
                    Signature = signedHashResult.Value,
                    EncryptedData = encrypted,
                    Nonce = nonceResult.Value,
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
        public Result<byte[], Exception> Decrypt(ReadOnlyMemory<byte> encryptedData, ReadOnlySpan<byte> eccPublicKey, 
            ReadOnlySpan<byte> eccPrivateKey, EncryptionAlgorithm encryptionAlgorithm, Enums.HashAlgorithm hashAlgorithm, 
            ReadOnlySpan<byte> nonce,ReadOnlySpan<byte> eccSignature, SecureString password)
        {
            try
            {
                // Create Engine
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Derive the Key
                var keyResult = GenerateKey(eccPrivateKey, eccPublicKey, nonce, password);
                if (keyResult.IsFailure)
                    return Result.Failure<byte[], Exception>(keyResult.Error);

                // Decrypt
                var clearData = engine.Decrypt(encryptedData, keyResult.Value, nonce);

                // Compute Hash
                var hashResult = ComputeHash(clearData, hashAlgorithm);
                if (hashResult.IsFailure)
                    return Result.Failure<byte[], Exception>(hashResult.Error);

                // Verify Hash
                var verifyResult = VerifyHash(hashResult.Value, eccSignature, eccPublicKey);
                if (verifyResult.IsFailure)
                    return Result.Failure<byte[], Exception>(verifyResult.Error);
                if (verifyResult.Value == false)
                    return Result.Failure<byte[], Exception>(new CryptographicException("Invalid Signature"));

                return clearData;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:Decrypt {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        #region PrivateMethods
        private Result<bool, Exception> VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, 
            ReadOnlySpan<byte> eccPublicKey)
        {
            try
            {
                var publicKey = _asymmetricCipherUtilities.ReadPublicKey(eccPublicKey.ToArray());
                var dsaSignature = ECDsaSignature.FromByteArray(signature.ToArray());

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

        private Result<byte[], Exception> ComputeHash(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            return _cryptoSharkUtilities.Hash(data, hashAlgorithm);
        }

        private Result<byte[], Exception> SignHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> eccPrivateKey, SecureString password)
        {   
            try
            {
                var privateKey = _asymmetricCipherUtilities.ReadKeyPair(eccPrivateKey.ToArray(), password).Private;

                var signer = new ECDsaSigner();
                signer.Init(true, privateKey);
                var signature = signer.GenerateSignature(hash.ToArray());

                ECDsaSignature dsaSignature = new ECDsaSignature(signature[0], signature[1]);

                return dsaSignature.ToArray();               
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:SignHash {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<byte[], Exception> GenerateSalt(int size = 16)
        {
            try
            {
                var salt = new byte[size];                
                _secureRandom.NextBytes(salt);

                return salt;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:GenerateSalt {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<byte[], Exception> GenerateKey(ReadOnlySpan<byte> eccPrivateKey, ReadOnlySpan<byte> eccPublicKey,
            ReadOnlySpan<byte> salt, SecureString password)
        {            
            try
            {
                byte[] derivedKey = new byte[256 / 8];

                var privateKey = _asymmetricCipherUtilities.ReadKeyPair(eccPrivateKey.ToArray(), password).Private;
                var publicKey = _asymmetricCipherUtilities.ReadPublicKey(eccPublicKey.ToArray());

                var exch = new Org.BouncyCastle.Crypto.Agreement.ECDHBasicAgreement();
                exch.Init(privateKey);
                var seed = exch.CalculateAgreement(publicKey).ToByteArray();

                var hkdf = new HkdfBytesGenerator(new Sha3Digest());
                hkdf.Init(new HkdfParameters(seed, salt.ToArray(), null));                
                hkdf.GenerateBytes(derivedKey, 0, derivedKey.Length);

                return derivedKey;

            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:GenerateKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }       

        #endregion
    }
}
