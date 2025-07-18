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
        const string DEFAULT_RSA_PADDING = "OAEPWithSHA-256AndMGF1Padding";

        private AsymetricEncryptionRequest(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> clearData, SecureString password, 
            EncryptionAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, string rsaPadding = null)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            ClearData = clearData;
            Password = password;
            EncryptionAlgorithm = encryptionAlgorithm;
            HashAlgorithm = hashAlgorithm;

            if(String.IsNullOrEmpty(rsaPadding))
                RsaPadding = DEFAULT_RSA_PADDING;
            else
                RsaPadding = rsaPadding;
        }

        private AsymetricEncryptionRequest(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> clearData, string password, 
            EncryptionAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, string rsaPadding = null)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            ClearData = clearData;            
            EncryptionAlgorithm = encryptionAlgorithm;
            HashAlgorithm = hashAlgorithm;           

            if (String.IsNullOrEmpty(rsaPadding))
                RsaPadding = DEFAULT_RSA_PADDING;
            else
                RsaPadding = rsaPadding;

            Password = new SecureString();
            foreach (var c in password.ToCharArray())
                Password.AppendChar(c);

            Password.MakeReadOnly();
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> PublicKey { get; private set; }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> PrivateKey { get; private set; }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> ClearData { get; private set; }

        /// <inheritdoc />
        public SecureString Password { get; private set; }

        /// <inheritdoc />
        public EncryptionAlgorithm EncryptionAlgorithm { get; private set; }

        /// <inheritdoc />
        public HashAlgorithm HashAlgorithm { get; private set; }

        /// <inheritdoc />
        public string RsaPadding { get; private set; }


        public static IAsymetricEncryptionRequest CreateRequest(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> clearData, SecureString password, EncryptionAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, string rsaPadding = null)
            => new AsymetricEncryptionRequest(publicKey, privateKey, clearData, password, encryptionAlgorithm, hashAlgorithm, rsaPadding);
        
        public static IAsymetricEncryptionRequest CreateRequest(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> clearData, string password, EncryptionAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, string rsaPadding = null)
            => new AsymetricEncryptionRequest(publicKey, privateKey, clearData, password, encryptionAlgorithm, hashAlgorithm, rsaPadding);
     
    }
}
