using System;
using System.Linq;
using System.Security.Cryptography;
using CryptoShark.Interfaces;

namespace CryptoShark
{
    internal class Utilities : IRSAUtilites
    {
        private static Lazy<Utilities> _utilities = new Lazy<Utilities>(() => new Utilities(), true);
        public static Utilities Instance => _utilities.Value;

        ///<inheritdoc/>
        public Exception LastException { get; private set; } = null;

        /// <summary>
        ///     Hide Constructor
        /// </summary>
        private Utilities()
        {
        }

        #region IRSAUtilites
        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.CreateRsaKey(int keyLength)
        {
            try
            {
                if (!Enumerable.Range(1024, 16384).Contains(keyLength))
                    throw new ArgumentOutOfRangeException("Keysize must be between 1024 and 16384");
                if (keyLength % 8 != 0)
                    throw new ArgumentOutOfRangeException($"Keysize must be divisible by 8");

                using (var rsa = RSA.Create(keyLength))
                {
                    return rsa.ExportPkcs8PrivateKey();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
        }


        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.EncryptRsaKey(ReadOnlySpan<byte> rsaKey, string password)
        {            
            try
            {
                using (var rsa = RSA.Create())
                {
                    rsa.ImportPkcs8PrivateKey(rsaKey, out var _);
                    return rsa.ExportEncryptedPkcs8PrivateKey(password,
                        new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA384, 10000));
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.EncryptRsaKey(ReadOnlySpan<byte> rsaKey,
            string password,
            PbeEncryptionAlgorithm encryptionAlgorithm,
            HashAlgorithmName hashAlgorithm,
            int itterations)
        {
            try
            {
                using (var rsa = RSA.Create())
                {
                    rsa.ImportPkcs8PrivateKey(rsaKey, out var _);
                    return rsa.ExportEncryptedPkcs8PrivateKey(password,
                        new PbeParameters(encryptionAlgorithm, hashAlgorithm, itterations));
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.GetRsaPublicKey(ReadOnlySpan<byte>unencryptedRsaKey)
        {
            try
            {
                using (var rsa = RSA.Create())
                {
                    rsa.ImportPkcs8PrivateKey(unencryptedRsaKey, out var _);
                    return rsa.ExportRSAPublicKey();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.GetRsaPublicKey(ReadOnlySpan<byte> encryptedRsaKey, string password)
        {
            try
            {
                using (var rsa = RSA.Create())
                {
                    rsa.ImportEncryptedPkcs8PrivateKey(password, encryptedRsaKey, out var _);
                    return rsa.ExportRSAPublicKey();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
        }
        #endregion       
    }
}
