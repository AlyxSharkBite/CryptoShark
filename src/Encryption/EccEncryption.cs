using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Record;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger">ILogger</param>
        public EccEncryption(ILogger logger)
        {
            _logger = logger;
            _cryptoSharkUtilities = new CryptoSharkUtilities(logger);
            _secureStringUtilities = new SecureStringUtilities();
        }

        /// <summary>
        ///     Encrypts Data useing the ECC Keys Specified
        ///     With specified encryption algorithm
        /// </summary>
        /// <param name="clearData">Data to encrypt</param>
        /// <param name="eccPublicKey">ECC Key to Encrypt WITH</param>
        /// <param name="eccPrivateKey">ECC Key to Sign WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="password">Password for Private Key</param>    
        /// <returns></returns>
        public Result<EccCryptographyRecord, Exception> Encrypt(ReadOnlyMemory<byte> clearData, ReadOnlySpan<byte> eccPublicKey,
            ReadOnlySpan<byte> eccPrivateKey, EncryptionAlgorithm encryptionAlgorithm, SecureString password)
        {
            try
            {
                var engine = new EncryptionEngine(encryptionAlgorithm);                

                // Generate Data
                var nonceResult = GenerateSalt();
                if (nonceResult.IsFailure)
                    return Result.Failure<EccCryptographyRecord, Exception>(nonceResult.Error);

                var keyResult = GenerateKey(eccPrivateKey, eccPublicKey, password);
                if(keyResult.IsFailure)
                    return Result.Failure<EccCryptographyRecord, Exception>(keyResult.Error);

                var hashResult = ComputeHash(clearData);
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
                    Algorithm = encryptionAlgorithm,
                    PublicKey = eccPublicKey.ToArray(),
                    Signature = signedHashResult.Value,
                    EncryptedData = encrypted,
                    Nonce = nonceResult.Value
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
        public Result<byte[], Exception> Decrypt(ReadOnlyMemory<byte> encryptedData, ReadOnlySpan<byte> eccPublicKey, ReadOnlySpan<byte> eccPrivateKey, 
            EncryptionAlgorithm encryptionAlgorithm, ReadOnlySpan<byte> nonce,ReadOnlySpan<byte> eccSignature, SecureString password)
        {
            try
            {
                // Create Engine
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Derive the Key
                var keyResult = GenerateKey(eccPrivateKey, eccPublicKey, password);
                if (keyResult.IsFailure)
                    return Result.Failure<byte[], Exception>(keyResult.Error);

                // Decrypt
                var clearData = engine.Decrypt(encryptedData, keyResult.Value, nonce);

                // Compute Hash
                var hashResult = ComputeHash(clearData);
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
                using var dsa = ECDsaCng.Create();               
                dsa.ImportSubjectPublicKeyInfo(eccPublicKey, out var _);

                return dsa.VerifyHash(hash.ToArray(), signature.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:VerifyHash {message}", ex.Message);
                return Result.Failure<bool, Exception>(ex);
            }
        }

        private Result<byte[], Exception> ComputeHash(ReadOnlyMemory<byte> data)
        {
            return _cryptoSharkUtilities.Hash(data, Enums.HashAlgorithm.SHA2_384);
        }

        private Result<byte[], Exception> SignHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> eccPrivateKey, SecureString password)
        {   
            try
            {
                using var dsa = ECDsaCng.Create();
                dsa.ImportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password), eccPrivateKey, out var _); ;

                return dsa.SignHash(hash.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
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
                using RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetNonZeroBytes(salt);

                return salt;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:EccEncryption:GenerateSalt {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<byte[], Exception> GenerateKey(ReadOnlySpan<byte> eccPrivateKey, ReadOnlySpan<byte> eccPublicKey, SecureString password)
        {            
            try
            {
                using var diffieHellman = ECDiffieHellmanCng.Create();
                using var diffieHellman2 = ECDiffieHellmanCng.Create();                

                diffieHellman.ImportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password), eccPrivateKey, out var _); ;
                diffieHellman2.ImportSubjectPublicKeyInfo(eccPublicKey, out var _);

                return diffieHellman.DeriveKeyFromHash(diffieHellman2.PublicKey, HashAlgorithmName.SHA256)
                    .Take(KEY_SIZE / 8)
                    .ToArray();
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
