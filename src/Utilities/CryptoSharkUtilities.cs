using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

[assembly: InternalsVisibleTo("CryptoSharkTests")]
namespace CryptoShark.Utilities
{    
    internal sealed class CryptoSharkUtilities(ILogger logger)
    {        
        private readonly SecureStringUtilities _secureStringUtilities = new SecureStringUtilities();
        private readonly AsymmetricCipherUtilities _asymmetricCipherUtilities = new AsymmetricCipherUtilities();
        private readonly ILogger _logger = logger;

        public Result<byte[], Exception> CreateEccKey(ECCurve curve, SecureString password, bool useDotNet)
        { 
            try
            {
                curve.Validate();

                var keyPair = _asymmetricCipherUtilities.GenerateECDHKeyPair(curve, useDotNet);
                return _asymmetricCipherUtilities.WritePrivateKey(keyPair.Private, password);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:CreateEccKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }            
        }

        public Result<byte[], Exception> GetEccPublicKey(ReadOnlySpan<byte> encryptedEccKey, SecureString password)
        {
            try
            {
                var privateKey = _asymmetricCipherUtilities.ReadPrivateKey(encryptedEccKey.ToArray(), password);
                var publicKey = _asymmetricCipherUtilities.GetPublicKey(privateKey);
                return _asymmetricCipherUtilities.WritePublicKey(publicKey);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:GetEccPublicKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<byte[], Exception> CreateRsaKey(RsaKeySize keySize, 
            SecureString password, bool useDotNet)
        {
            try
            {
                var keyPair = _asymmetricCipherUtilities.GenerateRsaKeyPair(
                    (int)keySize,
                    useDotNet);                
                
                return _asymmetricCipherUtilities.WritePrivateKey(keyPair.Private, password);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:CreateRsaKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<byte[], Exception> GetRsaPublicKey(ReadOnlySpan<byte> encryptedRsaKey, SecureString password)
        {           
            try
            {
                var privateKey = _asymmetricCipherUtilities.ReadPrivateKey(encryptedRsaKey.ToArray(), password);
                var publicKey = _asymmetricCipherUtilities.GetPublicKey(privateKey);
                return _asymmetricCipherUtilities.WritePublicKey(publicKey);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:GetRsaPublicKey {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<string, Exception> Hash(ReadOnlyMemory<byte> data, Enums.StringEncoding encoding, 
            Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hash(data.ToArray().ToArray(), encoding);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hash {message}", ex.Message);
                return Result.Failure<string, Exception>(ex);
            }
        }

        public Result<byte[], Exception> Hash(ReadOnlyMemory<byte> data, 
            Enums.HashAlgorithm hashAlgorithm)
        {
            try 
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hash(data.ToArray());
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hash {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }
        
        public Result<byte[], Exception> Hmac(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key, 
            Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hmac(data.ToArray(), key);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hmac {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        public Result<string, Exception> Hmac(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key, 
            Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            try
            {
                var engine = new Engine.HashEngine(hashAlgorithm);
                return engine.Hmac(data.ToArray(), key, encoding);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkUtilities:Hmac {message}", ex.Message);
                return Result.Failure<string, Exception>(ex);
            }
        }

        public Result<ECCurve> ParseCurveFomOid(string oidString)
        {
            try
            {
                return ECCurve.CreateFromOid(
                    Oid.FromOidValue(
                        oidString, 
                        OidGroup.All)
                    );
            }
            catch (Exception ex) 
            {
                _logger?.LogError(ex, "Unable to parse Oid {oidString}", oidString);
                return Result.Failure<ECCurve>(ex.Message);
            }
        }

	}
}
