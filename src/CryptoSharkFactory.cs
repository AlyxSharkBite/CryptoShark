using CryptoShark.CryptographicProviders;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark
{
    /// <summary>
    /// CryptoSharkFactory For Creating CryptoSharkFactory Instances
    /// With Or Without Logging
    /// </summary>
    public static class CryptoSharkFactory
    {

        /// <summary>
        /// Creates a ICryptoSharkCryptographyUtilities Instance With Logging
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities CreateCryptographyUtilities(ILogger logger)
            => CryptoSharkCryptographyUtilities.Create(logger);

        /// <summary>
        /// Creates a ICryptoSharkCryptographyUtilities Instance Without Logging
        /// </summary>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities CreateCryptographyUtilities()
            => CryptoSharkCryptographyUtilities.Create();

        /// <summary>
        /// Creates a ICryptoSharkSymmetricCryptography Instance
        /// For The Specified CryptographyType With Logging
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="cryptographyType"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static ICryptoSharkSymmetricCryptography CreateSymmetricCryptography(ILogger logger, 
            CryptographyType cryptographyType = CryptographyType.PasswordBasedCryptography)
        {
            switch(cryptographyType)
            {
                case CryptographyType.PasswordBasedCryptography:
                    return CryptoSharkPasswordCryptography.Create(logger);
                default:
                    throw new ArgumentException($"Unsupprted CryptographyType {cryptographyType}");
            }
        }

        /// <summary>
        /// Creates a ICryptoSharkSymmetricCryptography Instance
        /// For The Specified CryptographyType Without Logging
        /// </summary>
        /// <param name="cryptographyType"></param>
        /// <returns></returns>
        public static ICryptoSharkSymmetricCryptography CreateSymmetricCryptography(
            CryptographyType cryptographyType = CryptographyType.PasswordBasedCryptography)
        {
            return CreateSymmetricCryptography(null, cryptographyType);
        }

        /// <summary>
        /// Creates a ICryptoSharkAsymmetricCryptography Instance
        /// For The Specified CryptographyType With Logging
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="cryptographyType"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static ICryptoSharkAsymmetricCryptography CreateAsymmetricCryptography(ILogger logger,
            CryptographyType cryptographyType)
        {
            switch (cryptographyType)
            {
                case CryptographyType.EllipticalCurveCryptography:
                    return CryptoSharkEccCryptography.Create(logger);
                case CryptographyType.RivestShamirAdlemanCryptography:
                    return CryptoSharkRsaCryptography.Create(logger);                
                default:
                    throw new ArgumentException($"Unsupprted CryptographyType {cryptographyType}"); ;
            }
        }

        /// <summary>
        /// Creates a ICryptoSharkAsymmetricCryptography Instance
        /// For The Specified CryptographyType Without Logging
        /// </summary>
        /// <param name="cryptographyType"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography CreateAsymmetricCryptography(
            CryptographyType cryptographyType)
        {
            return CreateAsymmetricCryptography(null, cryptographyType);
        }
    }
}