using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark
{
    /// <summary>
    /// ECC Encryption
    /// </summary>
    public sealed class EccEncryption
    {
        private const int _keySize = 256;
        private IHash _hash => Utilities.Instance;

        /// <summary>
        ///     ECC Utilities 
        /// </summary>
        public static IECCUtilities ECCUtilities => Utilities.Instance;

        /// <summary>
        ///     Encrypts Data useing the ECC Keys Specified
        ///     With specified encryption algorithm
        /// </summary>
        /// <param name="clearData">Data to encrypt</param>
        /// <param name="eccPublicKey">RSA Key to Encrypt WITH</param>
        /// <param name="eccPrivateKey">RSA Key to Sign WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="password">OPTIONAL - Password if Private Key is Encrypted</param>        
        /// <returns></returns>
        public Dto.ECCEncryptionResult Encrypt(ReadOnlySpan<byte> clearData, ReadOnlySpan<byte> eccPublicKey, ReadOnlySpan<byte> eccPrivateKey, 
            EncryptionAlgorithm encryptionAlgorithm, string password = null)
        {
            var engine = new EncryptionEngine(encryptionAlgorithm);

            // Generate Data
            var gcmNonce = GenerateSalt();
            var key = String.IsNullOrWhiteSpace(password) ? GenerateKey(eccPrivateKey, eccPublicKey) : GenerateKey(DecrypEcctKey(eccPrivateKey, password), eccPublicKey);
            var hash = ComputeHash(clearData);

            // Encrypt
            var encrypted = engine.Encrypt(clearData, key, gcmNonce);

            // Build the response
            return new Dto.ECCEncryptionResult
            {
                EncryptedData = encrypted.ToArray(),
                GcmNonce = gcmNonce.ToArray(),
                Algorithm = encryptionAlgorithm,
                ECCPublicKey = ECCUtilities.GetEccPublicKey(eccPrivateKey).ToArray(),
                ECCSignature = SignHash(hash, eccPrivateKey).ToArray()
            };
        }


        /// <summary>
        ///     Decrypts Previously Encrypted Data
        /// </summary>
        /// <param name="encryptedData">Encrypted Data</param>
        /// <param name="eccPublicKey">Publi Key to Verify Signature WITH</param>
        /// <param name="eccPrivateKey">Private Key to Decrypt WITH</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="gcmNonce">Nonce Token</param>
        /// <param name="eccSignature">Signature</param>     
        /// <param name="password">OPTIONAL - Password if Private Key is Encrypted</param> 
        /// <returns></returns>
        public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encryptedData, ReadOnlySpan<byte> eccPublicKey, ReadOnlySpan<byte> eccPrivateKey, EncryptionAlgorithm encryptionAlgorithm, 
            ReadOnlySpan<byte> gcmNonce, ReadOnlySpan<byte> eccSignature, string password = null)
        {
            // Create Engine
            var engine = new EncryptionEngine(encryptionAlgorithm);

            // Derive the Key
            var key = String.IsNullOrWhiteSpace(password) ? GenerateKey(eccPrivateKey, eccPublicKey) : GenerateKey(DecrypEcctKey(eccPrivateKey, password), eccPublicKey); 

            // Decrypt
            var clearData = engine.Decrypt(encryptedData, key, gcmNonce);

            // Verify Signature
            if (!VerifyHash(ComputeHash(clearData), eccSignature, eccPublicKey))
                throw new CryptographicException("Invalid Signature");

            return clearData;
        }

        #region PrivateMethods
        private bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> eccPublicKey)
        {
            ECDsa dsa = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    dsa = new ECDsaCng();
                else
                    dsa = ECDsa.Create();

                dsa.ImportSubjectPublicKeyInfo(eccPublicKey, out var _);
                
                return dsa.VerifyHash(hash.ToArray(), signature.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            finally
            {
                if (dsa != null)
                    dsa.Dispose();
            }
        }

        private ReadOnlySpan<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            return _hash.Hash(data, Enums.HashAlgorithm.SHA2_384);
        }

        private ReadOnlySpan<byte> SignHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> eccPrivateKey)
        {
            ECDsa dsa = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    dsa = new ECDsaCng();
                else
                    dsa = ECDsa.Create();

                dsa.ImportPkcs8PrivateKey(eccPrivateKey, out var _);

                return dsa.SignHash(hash.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            finally
            {
                if (dsa != null)
                    dsa.Dispose();
            }            
        }

        private ReadOnlySpan<byte> GenerateSalt(int size = 16)
        {
            var salt = new byte[size];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetNonZeroBytes(salt);

            return salt;
        }

        private ReadOnlySpan<byte> GenerateKey(ReadOnlySpan<byte> eccPrivateKey, ReadOnlySpan<byte> eccPublicKey)
        {
            ECDiffieHellman diffieHellman = null;
            ECDiffieHellman diffieHellman2 = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                {
                    diffieHellman = new ECDiffieHellmanCng();
                    diffieHellman2 = new ECDiffieHellmanCng();
                }
                else
                {
                    diffieHellman = ECDiffieHellman.Create();
                    diffieHellman2 = ECDiffieHellman.Create();
                }

                diffieHellman.ImportPkcs8PrivateKey(eccPrivateKey, out var _);
                diffieHellman2.ImportSubjectPublicKeyInfo(eccPublicKey, out var _);

                return diffieHellman.DeriveKeyFromHash(diffieHellman2.PublicKey, HashAlgorithmName.SHA256)
                    .Take(_keySize / 8)
                    .ToArray();
            }
            finally
            {
                if (diffieHellman != null) 
                    diffieHellman.Dispose();
                if (diffieHellman2 != null)
                    diffieHellman2.Dispose();
            }
        }

        private ReadOnlySpan<byte> DecrypEcctKey(ReadOnlySpan<byte> eccPrivateKey, string password)
        {
            ECDiffieHellman diffieHellman = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    diffieHellman = new ECDiffieHellmanCng();
                else
                    diffieHellman = ECDiffieHellman.Create();

                diffieHellman.ImportEncryptedPkcs8PrivateKey(password.ToCharArray(), eccPrivateKey, out var _);

                return diffieHellman.ExportPkcs8PrivateKey();

            }
            finally
            {
                if (diffieHellman != null)
                    diffieHellman.Dispose();
            }

        }      

        #endregion
    }
}
