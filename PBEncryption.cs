using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using CryptoShark.Engine;
using System.Text;

namespace CryptoShark
{
    /// <summary>
    ///     Password Based Encryption
    /// </summary>
    public class PBEncryption
    {
        private const int _keySize = 256;
        private Random _random = new Random();        

        /// <summary>
        ///     Encrypts the specified data with specified algorithm
        ///     and specified key size
        /// </summary>
        /// <param name="clearData">Data to Encrypt</param>
        /// <param name="password">Password to use for Encryption</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm to use</param>        
        /// <returns>Encryption Results</returns>
        public Dto.PBEncryptionResult Encrypt(ReadOnlySpan<byte> clearData,
            string password,
            EncryptionAlgorithm encryptionAlgorithm)
        {
            var engine = new EncryptionEngine(encryptionAlgorithm);

            // Create our paramaters 
            var gcmNonce = GenerateSalt();
            var pbkdfSalt = GenerateSalt();
            var itterations = _random.Next(10000, 50000);
            var key = PasswordDeriveBytes(password, pbkdfSalt, _keySize, itterations);
            var hash = Hash(clearData.ToArray(), key);            

            // Encrypt
            var encrypted = engine.Encrypt(clearData, key, gcmNonce);

            return new Dto.PBEncryptionResult(encrypted, gcmNonce, encryptionAlgorithm, hash, itterations, pbkdfSalt);

        }

        /// <summary>
        ///     Decrypts the previously encypted data
        /// </summary>
        /// <param name="encryptedData">Encrypted Data</param>
        /// <param name="password">Password</param>
        /// <param name="algorithm">Encryption Algorithm</param>
        /// <param name="gcmNonce">GCM Nonce Token</param>
        /// <param name="pbkdfSalt">PBKDF2 Salt</param>
        /// <param name="sha384Hmac">Hash of Decrypted Data</param>
        /// <param name="itterations">Itterations for the PBKDF2 Key Derivation</param>                
        /// <returns></returns>
        public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encryptedData,
            string password,
            EncryptionAlgorithm algorithm,
            ReadOnlySpan<byte> gcmNonce,
            ReadOnlySpan<byte> pbkdfSalt,
            ReadOnlySpan<byte> sha384Hmac,
            int itterations)
        {
            // Create the Engine
            var engine = new EncryptionEngine(algorithm);

            // Generate the Key
            var key = PasswordDeriveBytes(password, pbkdfSalt, _keySize, itterations);

            // Decrypt the Data
            var decrypted = engine.Decrypt(encryptedData, key, gcmNonce);

            // Validate Hash
            var verify = Hash(decrypted, key);
            if (!verify.SequenceEqual(sha384Hmac))
                throw new CryptographicException($"Hash Of Decrypoted Data Does Not Match: Got 0x{BitConverter.ToString(verify.ToArray()).Replace("-", String.Empty)} Exptected {BitConverter.ToString(sha384Hmac.ToArray()).Replace("-", String.Empty)}");
            
            return decrypted;            
        }

        private ReadOnlySpan<byte> PasswordDeriveBytes(string password, ReadOnlySpan<byte> salt, int keySize, int itterations)
        {            
            using (var deriveyutes = new Rfc2898DeriveBytes(password, salt.ToArray(), itterations, HashAlgorithmName.SHA512))
                return deriveyutes.GetBytes(keySize / 8);
        }

        private ReadOnlySpan<byte> GenerateSalt(int size = 16)
        {
            var salt = new byte[size];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetNonZeroBytes(salt);

            return salt;
        }
        
        private ReadOnlySpan<byte> Hash(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
        {
            var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Org.BouncyCastle.Crypto.Digests.Sha384Digest());
            byte[] result = new byte[hmac.GetMacSize()];

            hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key.ToArray()));

            hmac.BlockUpdate(data.ToArray(), 0, data.Length);
            hmac.DoFinal(result, 0);

            return result;
        }

    }
}
