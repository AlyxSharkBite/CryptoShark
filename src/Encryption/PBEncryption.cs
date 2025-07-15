using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Record;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

[assembly: InternalsVisibleTo("CryptoSharkTests")]
namespace CryptoShark
{
    /// <summary>
    ///     Password Based Encryption
    /// </summary>
    internal sealed class PBEncryption
    {
        private const int KEY_SIZE = 256;
        private readonly ILogger _logger;
        private readonly CryptoSharkUtilities _cryptoSharkUtilities;
        private readonly SecureStringUtilities _secureStringUtilities;
        private readonly SecureRandom _secureRandom;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        public PBEncryption(ILogger logger)
        {
            _logger = logger;
            _secureStringUtilities = new SecureStringUtilities();
            _cryptoSharkUtilities = new CryptoSharkUtilities(logger);
            _secureRandom = new SecureRandom();
        }

        /// <summary>
        ///     Encrypts the specified data with specified algorithm        
        /// </summary>
        /// <param name="clearData">Data to Encrypt</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm to use</param> 
        /// <param name="hashAlgorithm">Hashing Algorithm to use</param> 
        /// <param name="password">Password for encryption</param>        
        /// <returns>Encryption Results</returns>
        public Result<PbeCryptographyRecord, Exception> Encrypt(ReadOnlyMemory<byte> clearData, EncryptionAlgorithm encryptionAlgorithm,
            CryptoShark.Enums.HashAlgorithm hashAlgorithm, SecureString password)
        {
            try
            {
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Create our paramaters 
                var itterations = _secureRandom.Next(10000, 500000);
                
                var nonceResult = GenerateSalt();
                if (nonceResult.IsFailure)
                    return Result.Failure<PbeCryptographyRecord, Exception>(nonceResult.Error);

                var saltResult = GenerateSalt();
                if (saltResult.IsFailure)
                    return Result.Failure<PbeCryptographyRecord, Exception>(saltResult.Error);

                var keyResult = PasswordDeriveBytes(password, saltResult.Value, KEY_SIZE, itterations);
                if (keyResult.IsFailure)
                    return Result.Failure<PbeCryptographyRecord, Exception>(keyResult.Error);

                var hashResult = _cryptoSharkUtilities.Hmac(clearData, keyResult.Value, hashAlgorithm);
                if (hashResult.IsFailure)
                    return Result.Failure<PbeCryptographyRecord, Exception>(hashResult.Error);

                // Encrypt
                var encrypted = engine.Encrypt(clearData, keyResult.Value, nonceResult.Value);

                return new PbeCryptographyRecord
                {
                    EncryptionAlgorithm = encryptionAlgorithm,
                    EncryptedData = encrypted,
                    Hash = hashResult.Value,
                    Iterations = itterations,
                    Nonce = nonceResult.Value,
                    Salt = saltResult.Value,
                    HashAlgorithm = hashAlgorithm
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:PBEncryption:Encrypt {message}", ex.Message);
                return Result.Failure<PbeCryptographyRecord, Exception>(ex);
            }
        }

        /// <summary>
        ///     Decrypts the previously encypted data
        /// </summary>
        /// <param name="encryptedData">Encrypted Data</param>
        /// <param name="password">Password for decryption</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="hashAlgorithm">Hashing Algorithm to use</param> 
        /// <param name="nonce">GCM Nonce Token</param>
        /// <param name="salt">PBKDF2 Salt</param>
        /// <param name="hmacHash">Hash of Decrypted Data</param>
        /// <param name="itterations">Iterations for the PBKDF2 Key Derivation</param>                
        /// <returns></returns>
        public Result<byte[], Exception> Decrypt(byte[] encryptedData, SecureString password, EncryptionAlgorithm encryptionAlgorithm,
            CryptoShark.Enums.HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hmacHash, int itterations)
        {
            try
            {
                // Create the Engine
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Generate the Key
                var keyTsk = PasswordDeriveBytes(password, salt, KEY_SIZE, itterations);
                if (keyTsk.IsFailure)
                    return Result.Failure<byte[], Exception>(keyTsk.Error);

                // Decrypt the Data
                var decrypted = engine.Decrypt(encryptedData, keyTsk.Value, nonce);

                // Validate Hash
                var verifyTask = _cryptoSharkUtilities.Hmac(decrypted.AsMemory(), keyTsk.Value, hashAlgorithm);
                if (verifyTask.IsFailure)
                    return Result.Failure<byte[], Exception>(verifyTask.Error);

                if (!verifyTask.Value.SequenceEqual(hmacHash.ToArray()))
                    return Result.Failure<byte[], Exception>(new CryptographicException("Hash Of Decrypoted Data Does Not Match"));

                return decrypted;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:PBEncryption:Decrypt {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<byte[], Exception> PasswordDeriveBytes(SecureString password, ReadOnlySpan<byte> salt, int keySize, int itterations)
        {
            try
            {
                using (var deriveyutes = new Rfc2898DeriveBytes(_secureStringUtilities.SecureStringToString(password), salt.ToArray(), itterations, HashAlgorithmName.SHA512))
                    return deriveyutes.GetBytes(keySize / 8);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:PBEncryption:PasswordDeriveBytes {message}", ex.Message);
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
                _logger?.LogError(ex, "CryptoShark:PBEncryption:GenerateSalt {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }
    }
}
