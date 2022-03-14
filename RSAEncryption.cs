using System;
using System.Security.Cryptography;
using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;

namespace CryptoShark
{
    /// <summary>
    ///     RSA Encryption
    /// </summary>
    public sealed class RsaEncryption
    {
        private const int _keySize = 256;
        private IHash _hash => Utilities.Instance;        

        /// <summary>
        ///     RSA Utilities 
        /// </summary>
        public static IRSAUtilites RSAUtilities => Utilities.Instance;

        /// <summary>
        ///     Encrypts Data useing the RSA Keys Specified
        ///     With specified encryption algorithm
        /// </summary>
        /// <param name="clearData">Data to encrypt</param>
        /// <param name="rsaPublicKey">RSA Key to Encrypt WITH</param>
        /// <param name="rsaPrivateKey">RSA Key to Sign WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>        
        /// <returns></returns>
        public Dto.RSAEncryptionResult Encrypt(ReadOnlySpan<byte> clearData,
            ReadOnlySpan<byte> rsaPublicKey,
            ReadOnlySpan<byte> rsaPrivateKey,
            EncryptionAlgorithm encryptionAlgorithm)
        {            
            var engine = new EncryptionEngine(encryptionAlgorithm);           

            // Generate Data
            var gcmNonce = GenerateSalt();
            var key = GenerateKey(_keySize);
            var hash = ComputeHash(clearData);

            // Encrypt
            var encrypted = engine.Encrypt(clearData, key, gcmNonce);

            // Build the response
            return new Dto.RSAEncryptionResult
            {
                EncryptedData = encrypted.ToArray(),
                GcmNonce = gcmNonce.ToArray(),
                Algorithm = encryptionAlgorithm,
                RSAPublicKey = RSAUtilities.GetRsaPublicKey(rsaPrivateKey).ToArray(),
                RSASignature = SignHash(hash, rsaPrivateKey).ToArray(),
                EncryptionKey = EncryptKey(key, rsaPublicKey).ToArray()
            };
        }       

        /// <summary>
        ///     Decrypts Previously Encrypted Data
        /// </summary>
        /// <param name="encryptedData">Encrypted Data</param>
        /// <param name="rsaPublicKey">Publi Key to Verify Signature WITH</param>
        /// <param name="rsaPrivateKey">Private Key to Decrypt WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="gcmNonce">Nonce Token</param>
        /// <param name="rsaSignature">Signature</param>
        /// <param name="rsaEncryptedKey">Encrypted Encryptuion Key</param>
        /// <returns></returns>
        public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encryptedData,
            ReadOnlySpan<byte> rsaPublicKey,
            ReadOnlySpan<byte> rsaPrivateKey,            
            EncryptionAlgorithm encryptionAlgorithm,
            ReadOnlySpan<byte> gcmNonce,
            ReadOnlySpan<byte> rsaSignature,
            ReadOnlySpan<byte> rsaEncryptedKey)
        {
            var engine = new EncryptionEngine(encryptionAlgorithm);

            // Decrypt Key            
            var key = DecryptKey(rsaEncryptedKey, rsaPrivateKey);

            // Decrypt the Data
            var clearData = engine.Decrypt(encryptedData, key, gcmNonce);

            // Validate Hash
            if (!VerifyHash(ComputeHash(clearData), rsaSignature, rsaPublicKey))
                throw new CryptographicException("Invalid Signature");

            return clearData;
        }

        #region PrivateMethods
        private ReadOnlySpan<byte> GenerateSalt(int size = 16)
        {
            var salt = new byte[size];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetNonZeroBytes(salt);

            return salt;
        }

        private ReadOnlySpan<byte> GenerateKey(int keySize)
        {
            Aes aes = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                aes = new AesCng();
            else
                aes = Aes.Create();

            try
            {
                aes.KeySize = keySize;
                aes.GenerateKey();
                return aes.Key;
            }
            finally
            {
                if(aes != null)
                    aes.Dispose();  
            }            
        }

        private ReadOnlySpan<byte> EncryptKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> rsaPublicKey)
        {
            RSA rsa = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                rsa = new RSACng();
            else
                rsa = RSA.Create();

            try
            {
                rsa.ImportRSAPublicKey(rsaPublicKey, out var _);
                return rsa.Encrypt(key.ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            finally
            { 
                if(rsa != null)
                    rsa.Dispose();
            }
            
        }

        private ReadOnlySpan<byte> DecryptKey(ReadOnlySpan<byte> encryptedKey, ReadOnlySpan<byte> rsaPrivateKey)
        {
            RSA rsa = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                rsa = new RSACng();
            else
                rsa = RSA.Create();

            try
            {
                rsa.ImportPkcs8PrivateKey(rsaPrivateKey, out var _);
                return rsa.Decrypt(encryptedKey.ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        private ReadOnlySpan<byte> DecryptKey(ReadOnlySpan<byte> encryptedKey, ReadOnlySpan<byte> rsaPrivateKey, string password)
        {
            RSA rsa = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                rsa = new RSACng();
            else
                rsa = RSA.Create();

            try
            {
                rsa.ImportEncryptedPkcs8PrivateKey(password, rsaPrivateKey, out var _);
                return rsa.Decrypt(encryptedKey.ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }       

        private ReadOnlySpan<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            return _hash.Hash(data, Enums.HashAlgorithm.SHA2_384);
        }

        private ReadOnlySpan<byte> SignHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> rsaPrivateKey)
        {
            RSA rsa = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                rsa = new RSACng();
            else
                rsa = RSA.Create();

            try
            {
                rsa.ImportPkcs8PrivateKey(rsaPrivateKey, out var _);
                return rsa.SignHash(hash.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        private ReadOnlySpan<byte> SignHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> rsaPrivateKey, string password)
        {
            RSA rsa = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                rsa = new RSACng();
            else
                rsa = RSA.Create();

            try
            {
                rsa.ImportEncryptedPkcs8PrivateKey(password, rsaPrivateKey, out var _);
                return rsa.SignHash(hash.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        private bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> rsaPublicKey)
        {
            RSA rsa = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                rsa = new RSACng();
            else
                rsa = RSA.Create();

            try
            {
                rsa.ImportRSAPublicKey(rsaPublicKey, out var _);
                return rsa.VerifyHash(hash.ToArray(), signature.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        #endregion
    }
}
