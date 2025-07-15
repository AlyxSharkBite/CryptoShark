using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Record;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
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
        private readonly ILogger _logger;
        private readonly CryptoSharkUtilities _cryptoSharkUtilities;
        private readonly SecureStringUtilities _secureStringUtilities;
        private readonly AsymmetricCipherUtilities _asymmetricCipherUtilities;

        public RsaEncryption(ILogger logger)
        {
            _logger = logger;
            _cryptoSharkUtilities = new CryptoSharkUtilities(logger);
            _secureStringUtilities = new SecureStringUtilities();
            _asymmetricCipherUtilities = new AsymmetricCipherUtilities();
        }

        
        public Result<RsaCryptographyRecord, Exception> Encrypt(ReadOnlyMemory<byte> clearData, ReadOnlySpan<byte> rsaPublicKey, 
            ReadOnlySpan<byte> rsaPrivateKey, Enums.EncryptionAlgorithm encryptionAlgorithm, Enums.HashAlgorithm hashAlgorithm,
            SecureString password, string rsaPadding)
        {
            try
            {
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Generate Data
                var nonceResult = GenerateSalt();
                if (nonceResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(nonceResult.Error);

                var keyResult = GenerateKey(encryptionAlgorithm.ToString());
                if (keyResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(keyResult.Error);

                var hashResult = ComputeHash(clearData, hashAlgorithm);
                if (hashResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(hashResult.Error);

                // Encrypt
                var encrypted = engine.Encrypt(clearData, keyResult.Value, nonceResult.Value);

                // Get Public Key
                var rsaPublicKeyResult = _cryptoSharkUtilities.GetRsaPublicKey(rsaPrivateKey, password);
                if (rsaPublicKeyResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(rsaPublicKeyResult.Error);

                // Encrypt the key
                var keyEncryptResult = EncryptKey(keyResult.Value, rsaPublicKeyResult.Value, rsaPadding);
                if (keyEncryptResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(keyEncryptResult.Error);

                // Sign Hash
                var hashSignResult = SignHash(hashResult.Value, rsaPrivateKey, password, hashAlgorithm);
                if (hashSignResult.IsFailure)
                    return Result.Failure<RsaCryptographyRecord, Exception>(hashSignResult.Error);

                return new RsaCryptographyRecord
                {
                    EncryptionAlgorithm = encryptionAlgorithm,
                    EncryptedData = encrypted,
                    EncryptionKey = keyEncryptResult.Value,
                    Nonce = nonceResult.Value,
                    PublicKey = rsaPublicKeyResult.Value,
                    Signature = hashSignResult.Value,
                    HashAlgorithm = hashAlgorithm,
                    RsaPadding = rsaPadding
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:Encrypt {message}", ex.Message);
                return Result.Failure<RsaCryptographyRecord, Exception>(ex);
            }

        }

        
        public Result<byte[], Exception> Decrypt(ReadOnlyMemory<byte> encryptedData, ReadOnlySpan<byte> rsaPublicKey, 
            ReadOnlySpan<byte> rsaPrivateKey, Enums.EncryptionAlgorithm encryptionAlgorithm, Enums.HashAlgorithm hashAlgorithm, 
            ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> rsaSignature, ReadOnlySpan<byte> rsaEncryptedKey, SecureString password, 
            string rsaPadding)
        {
            try
            {
                var engine = new EncryptionEngine(encryptionAlgorithm);

                // Decrypt Key            
                var keyResult = DecryptKey(rsaEncryptedKey, rsaPrivateKey, password, rsaPadding);
                if (keyResult.IsFailure)
                    return Result.Failure<byte[], Exception>(keyResult.Error);

                // Decrypt the Data
                var clearData = engine.Decrypt(encryptedData, keyResult.Value, nonce);

                // Compute Hash
                var hashResult = ComputeHash(clearData, hashAlgorithm);
                if (hashResult.IsFailure)
                    return Result.Failure<byte[], Exception>(hashResult.Error);

                // Verify Hash
                var verifyResult = VerifyHash(hashResult.Value, rsaSignature, rsaPublicKey, hashAlgorithm);
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

        private Result<byte[], Exception> GenerateKey(string algorithm)
        {
            try
            {
                var keyGenerator = GeneratorUtilities.GetKeyGenerator(algorithm);
                return keyGenerator.GenerateKey();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:GenerateKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<byte[], Exception> EncryptKey(ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> rsaPublicKey,
            string rsaPadding)
        {
            try
            {
                var publicKey = _asymmetricCipherUtilities.ReadPublicKey(rsaPublicKey.ToArray());
                var rsaEncryptor = _asymmetricCipherUtilities.ParsePadding(rsaPadding);
                rsaEncryptor.Init(true, publicKey);

                var cypheredEncryptionKey = rsaEncryptor.ProcessBlock(encryptionKey.ToArray(), 0, encryptionKey.Length);
                
                return cypheredEncryptionKey;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:EncryptKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }      

        private Result<byte[], Exception> DecryptKey(ReadOnlySpan<byte> cypheredEncryptionKey, ReadOnlySpan<byte> rsaPrivateKey, 
            SecureString password, string rsaPadding)
        {
            try
            {
                var privateKey = _asymmetricCipherUtilities.ReadKeyPair(rsaPrivateKey.ToArray(), password).Private;
                var rsaEncryptor = _asymmetricCipherUtilities.ParsePadding(rsaPadding);
                rsaEncryptor.Init(false, privateKey);

                var encryptionKey = rsaEncryptor.ProcessBlock(cypheredEncryptionKey.ToArray(), 0, cypheredEncryptionKey.Length);

                return encryptionKey;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:DecryptKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }       

        private Result<byte[], Exception> ComputeHash(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            return _cryptoSharkUtilities.Hash(data, hashAlgorithm);
        }       

        private Result<byte[], Exception> SignHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> rsaPrivateKey, 
            SecureString password, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var privateKey = _asymmetricCipherUtilities.ReadKeyPair(rsaPrivateKey.ToArray(), password).Private;

                var signer = new RsaDigestSigner(GetDigest(hashAlgorithm));
                signer.Init(true, privateKey);
                signer.BlockUpdate(hash.ToArray(), 0, hash.Length);
                
                return signer.GenerateSignature();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:SignHash {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<bool, Exception> VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, 
            ReadOnlySpan<byte> rsaPublicKey, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var publicKey = _asymmetricCipherUtilities.ReadPublicKey(rsaPublicKey.ToArray());

                var verifier = new RsaDigestSigner(GetDigest(hashAlgorithm));
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(hash.ToArray(), 0, hash.Length);

                return verifier.VerifySignature(signature.ToArray());
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:RsaEncryption:VerifyHash {message}", ex.Message);
                return Result.Failure<bool, Exception>(ex);
            }
        }

        private Org.BouncyCastle.Crypto.IDigest GetDigest(Enums.HashAlgorithm hashAlgorithm)
        {
            return DigestUtilities.GetDigest(hashAlgorithm.ToString());
        }        
    }
}
