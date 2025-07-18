using CryptoShark.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Interfaces
{
    public interface IRecordMarker
    {
        /// <summary>
        ///     The Encrypted Data
        /// </summary>
        byte[] EncryptedData { get; }

        /// <summary>
        ///     GCM Nonce Token
        ///     used to encrypt the data
        /// </summary>        
        public byte[] Nonce { get; }

        /// <summary>
        ///     Encryption Algorithm Used
        /// </summary>       
        public EncryptionAlgorithm EncryptionAlgorithm { get; }
    }

    public interface ISemetricRecordMarker : IRecordMarker
    {
        /// <summary>
        ///     HMAC Hash of the Unencrypted Data        
        /// </summary>        
        public byte[] Hash { get; }

        /// <summary>
        ///     Salt used in the PBKDF2 Key Derivation
        /// </summary>        
        public byte[] Salt { get; }

        /// <summary>
        ///     Number of iterations used in the
        ///     PBKDF2 Password Derivation 
        /// </summary>        
        public int Iterations { get; }
    }

    public interface IAsemetricRecordMarker : IRecordMarker
    {
        /// <summary>
        ///     Public Key for Derivation and Signature Verification
        /// </summary>        
        public byte[] PublicKey { get; }

        /// <summary>
        ///     Signature of the Decrypted Data
        /// </summary>        
        public byte[] Signature { get; }
    }
}
