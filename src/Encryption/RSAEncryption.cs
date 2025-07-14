using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Record;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using System;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;

[assembly: InternalsVisibleTo("CryptoSharkTests")]
namespace CryptoShark
{
    /// <summary>
    ///     RSA Encryption
    /// </summary>
    internal sealed class RsaEncryption
    {
        private const int KEY_SIZE = 256;        
        private readonly ILogger _logger;
        private readonly CryptoSharkUtilities _cryptoSharkUtilities;
        private readonly SecureStringUtilities _secureStringUtilities;

        public RsaEncryption(ILogger logger)
        {
            _logger = logger;
            _cryptoSharkUtilities = new CryptoSharkUtilities(logger);
            _secureStringUtilities = new SecureStringUtilities();
        }

        /// <summary>
        ///     Encrypts Data useing the RSA Keys Specified
        ///     With specified encryption algorithm
        /// </summary>
        /// <param name="clearData">Data to encrypt</param>
        /// <param name="rsaPublicKey">RSA Key to Encrypt WITH</param>
        /// <param name="rsaPrivateKey">RSA Key to Sign WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>       
        /// <param name="password">Password for Private Key</param> 
        /// <returns></returns>
        public Result<RsaCryptographyRecord, Exception> Encrypt(ReadOnlyMemory<byte> clearData, ReadOnlySpan<byte> rsaPublicKey, 
            ReadOnlySpan<byte> rsaPrivateKey, EncryptionAlgorithm encryptionAlgorithm, SecureString password)
        {
            try
            {
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Generate Data
                var nonceResult = GenerateSalt();
                if (nonceResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(nonceResult.Error);

                var keyResult = GenerateKey(KEY_SIZE);
                if (keyResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(keyResult.Error);

                var hashResult = ComputeHash(clearData);
                if (hashResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(hashResult.Error);

                // Encrypt
                var encrypted = engine.Encrypt(clearData, keyResult.Value, nonceResult.Value);

                // Get Public Key
                var rsaPublicKeyResult = _cryptoSharkUtilities.GetRsaPublicKey(rsaPrivateKey, password);
                if (rsaPublicKeyResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(rsaPublicKeyResult.Error);

                // Encrypt the key
                var keyEncryptResult = EncryptKey(keyResult.Value, rsaPublicKeyResult.Value);
                if (keyEncryptResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(keyEncryptResult.Error);

                // Sign Hash
                var hashSignResult = SignHash(hashResult.Value, rsaPrivateKey, password);
                if (hashSignResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(hashSignResult.Error);

                return new RsaCryptographyRecord
                {
                    Algorithm = encryptionAlgorithm,
                    EncryptedData = encrypted,
                    EncryptionKey = keyEncryptResult.Value,
                    Nonce = nonceResult.Value,
                    PublicKey = rsaPublicKeyResult.Value,
                    Signature = hashSignResult.Value
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:Encrypt {message}", ex.Message);
                return Result.Failure<RsaCryptographyRecord, Exception>(ex);
            }

        }

        /// <summary>
        ///     Decrypts Previously Encrypted Data
        /// </summary>
        /// <param name="encryptedData">Encrypted Data</param>
        /// <param name="rsaPublicKey">Publi Key to Verify Signature WITH</param>
        /// <param name="rsaPrivateKey">Private Key to Decrypt WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="nonce">Nonce Token</param>
        /// <param name="rsaSignature">Signature</param>
        /// <param name="rsaEncryptedKey">Encrypted Encryptuion Key</param>
        /// <param name="password">Password for encryption</param>
        /// <returns></returns>
        public Result<byte[], Exception> Decrypt(ReadOnlyMemory<byte> encryptedData, ReadOnlySpan<byte> rsaPublicKey, 
            ReadOnlySpan<byte> rsaPrivateKey, EncryptionAlgorithm encryptionAlgorithm, ReadOnlySpan<byte> nonce, 
            ReadOnlySpan<byte> rsaSignature, ReadOnlySpan<byte> rsaEncryptedKey, SecureString password)
        {
            try
            {
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Decrypt Key            
                var keyResult = DecryptKey(rsaEncryptedKey, rsaPrivateKey, password);
                if (keyResult.IsFailure)
                    return Result.Failure<byte[], Exception>(keyResult.Error);

                // Decrypt the Data
                var clearData = engine.Decrypt(encryptedData, keyResult.Value, nonce);

                // Compute Hash
                var hashResult = ComputeHash(clearData);
                if (hashResult.IsFailure)
                    return Result.Failure<byte[], Exception>(hashResult.Error);

                // Verify Hash
                var verifyResult = VerifyHash(hashResult.Value, rsaSignature, rsaPublicKey);
                if (verifyResult.IsFailure)
                    return Result.Failure<byte[], Exception>(verifyResult.Error);

                if (verifyResult.Value == false)
                    return Result.Failure<byte[], Exception>(new CryptographicException("Invalid Signature"));

                return clearData;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:Decrypt {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        #region PrivateMethods
        private Result<byte[], Exception> GenerateSalt(int size = 16)
        {
            try
            {
                var salt = new byte[size];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                    rng.GetNonZeroBytes(salt);

                return salt;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:GenerateSalt {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }

        }

        private Result<byte[], Exception> GenerateKey(int keySize)
        {
            try
            {
                using var aes = AesCng.Create();

                aes.KeySize = keySize;
                aes.GenerateKey();
                return aes.Key;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:GenerateKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<byte[], Exception> EncryptKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> rsaPublicKey)
        {
            try
            {
                using var rsa = RSACng.Create();

                rsa.ImportRSAPublicKey(rsaPublicKey, out var _);
                return rsa.Encrypt(key.ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:EncryptKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }      

        private Result<byte[], Exception> DecryptKey(ReadOnlySpan<byte> encryptedKey, ReadOnlySpan<byte> rsaPrivateKey, SecureString password)
        {
            try
            {
                using var rsa = RSACng.Create();

                rsa.ImportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password), rsaPrivateKey, out var _);
                return rsa.Decrypt(encryptedKey.ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:DecryptKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }       

        private Result<byte[], Exception> ComputeHash(ReadOnlyMemory<byte> data)
        {
            return _cryptoSharkUtilities.Hash(data, Enums.HashAlgorithm.SHA2_384);
        }       

        private Result<byte[], Exception> SignHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> rsaPrivateKey, SecureString password)
        {
            try
            {
                using var rsa = RSACng.Create();

                rsa.ImportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password), rsaPrivateKey, out var _);
                return rsa.SignHash(hash.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:SignHash {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<bool, Exception> VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> rsaPublicKey)
        {
            try
            {
                using var rsa = RSACng.Create();

                rsa.ImportRSAPublicKey(rsaPublicKey, out var _);
                return rsa.VerifyHash(hash.ToArray(), signature.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:VerifyHash {message}", ex.Message);
                return Result.Failure<bool, Exception>(ex);
            }
        }       

        #endregion
    }
}
