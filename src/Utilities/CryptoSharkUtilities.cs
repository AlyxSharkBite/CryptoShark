using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

[assembly: InternalsVisibleTo("CryptoSharkTests")]
namespace CryptoShark.Utilities
{    
    internal sealed class CryptoSharkUtilities(ILogger logger)
    {   
        private static readonly object _lock = new object();      
        private readonly SecureStringUtilities _secureStringUtilities = new SecureStringUtilities();

        public Result<byte[], Exception> CreateEccKey(ECCurve curve, SecureString password)
        { 
            try
            {
                curve.Validate();

                lock (_lock)
                {
                    using var diffieHellman = ECDiffieHellmanCng.Create(curve);
                    return diffieHellman.ExportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password),
                        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA384, 10000));
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:CreateEccKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }            
        }

        public Result<byte[], Exception> GetEccPublicKey(ReadOnlySpan<byte> encryptedEccKey, SecureString password)
        {
            try
            {
                lock (_lock)
                {
                    using var diffieHellman = ECDiffieHellmanCng.Create();

                    diffieHellman.ImportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password), encryptedEccKey, out var _);
                    return diffieHellman.ExportSubjectPublicKeyInfo();
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:GetEccPublicKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<byte[], Exception> CreateRsaKey(RsaKeySize keySize, SecureString password)
        {
            try
            {
                lock (_lock)
                {
                    using var rsa = RSACng.Create((int)keySize);
                    return rsa.ExportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password),
                       new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA384, 10000));
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:CreateRsaKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<byte[], Exception> GetRsaPublicKey(ReadOnlySpan<byte> encryptedRsaKey, SecureString password)
        {           
            try
            {
                lock (_lock)
                {
                    using var rsa = RSACng.Create();

                    rsa.ImportEncryptedPkcs8PrivateKey(_secureStringUtilities.SecureStringToString(password), encryptedRsaKey, out var _);
                    return rsa.ExportRSAPublicKey();
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:GetRsaPublicKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }
       
        public Result<string, Exception> Hash(ReadOnlySpan<byte> data, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hash(data.ToArray(), encoding);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hash {message}", ex.Message);
                return Result.Failure<string, Exception>(ex);
            }
        }

        public Result<string, Exception> Hash(ReadOnlyMemory<byte> data, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hash(data.ToArray().ToArray(), encoding);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hash {message}", ex.Message);
                return Result.Failure<string, Exception>(ex);
            }
        }

        public Result<byte[], Exception> Hash(ReadOnlySpan<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            try 
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hash(data.ToArray());
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hash {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<byte[], Exception> Hash(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hash(data.ToArray());
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hash {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<byte[], Exception> Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hmac(data.ToArray(), key);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hmac {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<byte[], Exception> Hmac(ReadOnlyMemory<byte> data, ReadOnlySpan<byte> key, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hmac(data.ToArray(), key);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hmac {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<string, Exception> Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hmac(data.ToArray(), key, encoding);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hmac {message}", ex.Message);
                return Result.Failure<string, Exception>(ex);
            }
        }

        public Result<string, Exception> Hmac(ReadOnlyMemory<byte> data, ReadOnlySpan<byte> key, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hmac(data.ToArray(), key, encoding);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hmac {message}", ex.Message);
                return Result.Failure<string, Exception>(ex);
            }
        }
    }
}
