using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Options;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.CryptographicProviders
{
    /// <inheritdoc />
    public sealed class CryptoSharkCryptographyUtilities : ICryptoSharkCryptographyUtilities
    {
        private readonly ILogger _logger;
        private readonly CryptoSharkUtilities _cryptoSharkUtilities;
        private readonly SecureStringUtilities _secureStringUtilities;

        public CryptoSharkCryptographyUtilities(ILogger logger)
        {
            _logger = logger;
            _cryptoSharkUtilities = new CryptoSharkUtilities(logger);
            _secureStringUtilities = new SecureStringUtilities();
        }

        /// <inheritdoc />
        public ReadOnlySpan<byte> CreateAsymetricKey(IAsymmetricKeyParameter parameters)
        {
            if (parameters is null) 
                throw new ArgumentNullException(nameof(parameters));    

            Result<byte[], Exception> keyResult;

            if (parameters.GetType() == typeof(EccKeyParameters)) 
            { 
                var eccParams = (EccKeyParameters)parameters;
                keyResult = _cryptoSharkUtilities.CreateEccKey(eccParams.Curve, eccParams.Password);
            }
            else if (parameters.GetType() == typeof(RsaKeyParameters))
            {
                var rsaParams = (RsaKeyParameters)parameters;
                keyResult = _cryptoSharkUtilities.CreateRsaKey(rsaParams.KeySize, rsaParams.Password);
            }
            else
            {
                _logger?.LogError("CryptoShark:CryptoSharkCryptographyUtilities:CreateAsymetricKey {message}", $"Unknown Type {parameters.GetType().Name}");
                keyResult = Result.Failure<byte[], Exception>(new Exception($"Unknown Type {parameters.GetType().Name}"));
            }

            if(keyResult.IsFailure)
                throw new CryptographicException("CreateAsymetricKey Failed, see inner exception(s)", keyResult.Error);

            return keyResult.Value.AsSpan();
        }

        /// <inheritdoc />
        public ReadOnlySpan<byte> HashBytes(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            var hashResult = _cryptoSharkUtilities.Hash(data, hashAlgorithm);
            if (hashResult.IsFailure)
                throw new CryptographicException("Hash Failed, see inner exception(s)", hashResult.Error);

            return hashResult.Value.AsSpan();
        }

        /// <inheritdoc />
        public string HashBytes(ReadOnlySpan<byte> data, Enums.HashAlgorithm hashAlgorithm, StringEncoding encoding)
        {
            var hashResult = _cryptoSharkUtilities.Hash(data, encoding, hashAlgorithm);
            if (hashResult.IsFailure)
                throw new CryptographicException("Hash Failed, see inner exception(s)", hashResult.Error);

            return hashResult.Value;
        }


        /// <inheritdoc />
        public ReadOnlySpan<byte> GetAsymetricPublicKey(ReadOnlySpan<byte> privateKey, SecureString password, 
            CryptographyType cryptographyType)
        {
            switch (cryptographyType)
            {
                case CryptographyType.EllipticalCurveCryptography:
                    {
                        var result = _cryptoSharkUtilities.GetEccPublicKey(privateKey, password);
                        if (result.IsFailure)
                            throw new CryptographicException("Failed to get public key, see inner exception(s)", result.Error);
                        return result.Value.AsSpan();
                    } 
                case CryptographyType.RivestShamirAdlemanCryptography:
                    {
                        var result = _cryptoSharkUtilities.GetRsaPublicKey(privateKey, password);
                        if (result.IsFailure)
                            throw new CryptographicException("Failed to get public key, see inner exception(s)", result.Error);
                        return result.Value.AsSpan();
                    }
                default:
                    throw new ArgumentException($"Invalid CryptographyType {cryptographyType}");
            }
        }

        /// <inheritdoc />
        public SecureString StringToSecureString(string value)
        {
            return _secureStringUtilities.StringToSecureString(value);
        }

        /// <summary>
        /// Creates a CryptoSharkCryptographyUtilities 
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities Create(ILogger logger)
            => new CryptoSharkCryptographyUtilities(logger);

        /// <summary>
        /// Creates a CryptoSharkCryptographyUtilities 
        /// </summary>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities Create()
            => new CryptoSharkCryptographyUtilities(null);


    }
}
