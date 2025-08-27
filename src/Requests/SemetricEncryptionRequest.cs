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
        private SemetricEncryptionRequest(
            ReadOnlyMemory<byte> clearData, SecureString password, EncryptionAlgorithm? encryptionAlgorithm,
            HashAlgorithm? hashAlgorithm, bool? compress)
        {
            ClearData = clearData;
            Password = password;
            EncryptionAlgorithm = encryptionAlgorithm;
            HashAlgorithm = hashAlgorithm;
            CompressData = compress;
        }

        private SemetricEncryptionRequest(
            ReadOnlyMemory<byte> clearData, char[] password, EncryptionAlgorithm? encryptionAlgorithm,
            HashAlgorithm? hashAlgorithm, bool? compress)
        {
            ClearData = clearData;            
            EncryptionAlgorithm = encryptionAlgorithm;
            HashAlgorithm = hashAlgorithm;
            CompressData = compress;

            Password = new SecureString();
            foreach (var c in password)
                Password.AppendChar(c);

            Password.MakeReadOnly();

            Array.Clear(password);
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> ClearData {  get; private set; }

        /// <inheritdoc />
        public SecureString Password { get; private set; }

        /// <inheritdoc />
        public EncryptionAlgorithm? EncryptionAlgorithm { get; private set; }

        /// <inheritdoc />
        public HashAlgorithm? HashAlgorithm { get; private set; }

        /// <inheritdoc />
        public bool? CompressData { get; private set; }

        public static IEncryptionRequest CreateRequest(ReadOnlyMemory<byte> clearData, SecureString password, EncryptionAlgorithm? encryptionAlgorithm = null, HashAlgorithm? hashAlgorithm = null, bool? compress = null) 
            => new SemetricEncryptionRequest(clearData, password, encryptionAlgorithm, hashAlgorithm, compress);
        
        public static IEncryptionRequest CreateRequest(ReadOnlyMemory<byte> clearData, char[] password, EncryptionAlgorithm? encryptionAlgorithm = null, HashAlgorithm? hashAlgorithm = null, bool? compress = null)
            => new SemetricEncryptionRequest(clearData, password, encryptionAlgorithm, hashAlgorithm, compress);
    }
}
