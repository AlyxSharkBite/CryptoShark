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
        private const string DEFAULT_RSA_PADDING = "OAEPWithSHA-256AndMGF1Padding";

        private AsymetricEncryptionRequest(
            byte[] publicKey, byte[] privateKey, byte[] clearData,
            SecureString password, EncryptionAlgorithm? encryptionAlgorithm, HashAlgorithm? hashAlgorithm,
            string rsaPadding, bool? compress)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            ClearData = clearData;
            Password = password;
            EncryptionAlgorithm = encryptionAlgorithm;
            HashAlgorithm = hashAlgorithm;
            CompressData = compress;

            if(String.IsNullOrEmpty(rsaPadding))
                RsaPadding = DEFAULT_RSA_PADDING;
            else
                RsaPadding = rsaPadding;
        }

        private AsymetricEncryptionRequest(
            byte[] publicKey, byte[] privateKey, byte[] clearData,
            char[] password, EncryptionAlgorithm? encryptionAlgorithm, HashAlgorithm? hashAlgorithm, string rsaPadding,
            bool? compress)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            ClearData = clearData;            
            EncryptionAlgorithm = encryptionAlgorithm;
            HashAlgorithm = hashAlgorithm;    
            CompressData = compress;

            if (String.IsNullOrEmpty(rsaPadding))
                RsaPadding = DEFAULT_RSA_PADDING;
            else
                RsaPadding = rsaPadding;

            Password = new SecureString();
            foreach (var c in password)
                Password.AppendChar(c);

            Password.MakeReadOnly();

            Array.Clear(password);
        }

        /// <inheritdoc />
        public byte[] PublicKey { get; private set; }

        /// <inheritdoc />
        public byte[] PrivateKey { get; private set; }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> ClearData { get; private set; }

        /// <inheritdoc />
        public SecureString Password { get; private set; }

        /// <inheritdoc />
        public EncryptionAlgorithm? EncryptionAlgorithm { get; private set; }

        /// <inheritdoc />
        public HashAlgorithm? HashAlgorithm { get; private set; }

        /// <inheritdoc />
        public string RsaPadding { get; private set; }

        /// <inheritdoc />
        public bool? CompressData { get; private set; }

        public static IAsymetricEncryptionRequest CreateRequest(byte[] publicKey, byte[] privateKey, byte[] clearData, SecureString password, EncryptionAlgorithm? encryptionAlgorithm = null, HashAlgorithm? hashAlgorithm = null, string rsaPadding = null, bool? compress = null)
            => new AsymetricEncryptionRequest(publicKey, privateKey, clearData, password, encryptionAlgorithm, hashAlgorithm, rsaPadding, compress);
        
        public static IAsymetricEncryptionRequest CreateRequest(byte[] publicKey, byte[] privateKey, byte[] clearData, char[] password, EncryptionAlgorithm? encryptionAlgorithm = null, HashAlgorithm? hashAlgorithm = null, string rsaPadding = null, bool? compress = null)
            => new AsymetricEncryptionRequest(publicKey, privateKey, clearData, password, encryptionAlgorithm, hashAlgorithm, rsaPadding, compress);
     
    }
}
