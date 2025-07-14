using CryptoShark.Enums;
using CryptoShark.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Requests
{
    public class AsymetricEncryptionRequest : IAsymetricEncryptionRequest
    {
        private AsymetricEncryptionRequest(byte[] publicKey, byte[] privateKey, byte[] clearData, SecureString password, EncryptionAlgorithm algorithm)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            ClearData = clearData;
            Password = password;
            Algorithm = algorithm;
        }

        private AsymetricEncryptionRequest(byte[] publicKey, byte[] privateKey, byte[] clearData, string password, EncryptionAlgorithm algorithm)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            ClearData = clearData;            
            Algorithm = algorithm;

            Password = new SecureString();
            foreach (var c in password.ToCharArray())
                Password.AppendChar(c);

            Password.MakeReadOnly();
        }

        /// <inheritdoc />
        public byte[] PublicKey { get; private set; }

        /// <inheritdoc />
        public byte[] PrivateKey { get; private set; }

        /// <inheritdoc />
        public byte[] ClearData { get; private set; }

        /// <inheritdoc />
        public SecureString Password { get; private set; }

        /// <inheritdoc />
        public EncryptionAlgorithm Algorithm { get; private set; }

        /// <summary>
        /// Create's the Encryption Request
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="password"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static IAsymetricEncryptionRequest CreateRequest(byte[] publicKey, byte[] privateKey, byte[] clearData, SecureString password, EncryptionAlgorithm algorithm)
            => new AsymetricEncryptionRequest(publicKey, privateKey, clearData, password, algorithm);

        /// <summary>
        /// Create's the Encryption Request
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="password"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static IAsymetricEncryptionRequest CreateRequest(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, ReadOnlyMemory<byte> clearData, SecureString password, EncryptionAlgorithm algorithm)
            => new AsymetricEncryptionRequest(publicKey.ToArray(), privateKey.ToArray(), clearData.ToArray(), password, algorithm);

        /// <summary>
        /// Create's the Encryption Request
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="password"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static IAsymetricEncryptionRequest CreateRequest(byte[] publicKey, byte[] privateKey, byte[] clearData, string password, EncryptionAlgorithm algorithm)
            => new AsymetricEncryptionRequest(publicKey, privateKey, clearData, password, algorithm);

        /// <summary>
        /// Create's the Encryption Request
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="password"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static IAsymetricEncryptionRequest CreateRequest(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, ReadOnlyMemory<byte> clearData, string password, EncryptionAlgorithm algorithm)
            => new AsymetricEncryptionRequest(publicKey.ToArray(), privateKey.ToArray(), clearData.ToArray(), password, algorithm);
    }
}
