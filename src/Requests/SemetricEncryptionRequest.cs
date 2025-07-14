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
    public class SemetricEncryptionRequest : IEncryptionRequest
    {
        private SemetricEncryptionRequest(byte[] clearData, SecureString password, EncryptionAlgorithm algorithm)
        {
            ClearData = clearData;
            Password = password;
            Algorithm = algorithm;
        }

        private SemetricEncryptionRequest(byte[] clearData, string password, EncryptionAlgorithm algorithm)
        {
            ClearData = clearData;            
            Algorithm = algorithm;

            Password = new SecureString();
            foreach (var c in password.ToCharArray())
                Password.AppendChar(c);

            Password.MakeReadOnly();
        }

        /// <inheritdoc />
        public byte[] ClearData {  get; private set; }

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
        public static IEncryptionRequest CreateRequest(byte[] clearData, SecureString password, EncryptionAlgorithm algorithm) 
            => new SemetricEncryptionRequest(clearData, password, algorithm);

        /// <summary>
        /// Create's the Encryption Request
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="password"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static IEncryptionRequest CreateRequest(byte[] clearData, string password, EncryptionAlgorithm algorithm)
            => new SemetricEncryptionRequest(clearData, password, algorithm);
    }
}
