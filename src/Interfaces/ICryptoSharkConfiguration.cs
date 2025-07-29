using CryptoShark.Enums;

namespace CryptoShark.Interfaces
{
    /// <summary>
    /// Allows setting defaults for various options
    /// Can be injected into CryptoSharkFactory or
    /// Supplied to each constructor
    /// </summary>
    public interface ICryptoSharkConfiguration
    {
        /// <summary>
        /// If set TRUE = Huffman Compression of data 
        /// before encryption
        /// </summary>
        bool? CompressBeforeEncryption { get; }

        /// <summary>
        /// If set OID will be used for cure generation
        /// Example NIST P256 is "1.2.840.10045.3.1.7"
        /// </summary>
        string DefaultEccCurveOid { get; }

        /// <summary>
        /// If set specifies the encryption algorithm
        /// to use.
        /// </summary>
        EncryptionAlgorithm? DefaultEncryptionAlgorithm { get; }

        /// <summary>
        /// If set specifies the hash algorithm
        /// to use.
        /// </summary>
        HashAlgorithm? DefaultHashAlgorithm { get; }

        /// <summary>
        /// If set specifies the RSA Key Size to use
        /// </summary>
        RsaKeySize? DefaultRsaKeySize { get; }

        /// <summary>
        /// If set specifies the default Pdding for
        /// RSA Encryption 
        /// Example: OAEPWithSHA-256AndMGF1Padding
        /// </summary>
        string DefaultRsaPadding { get; }

        /// <summary>
        /// If set TRUE will atempt to use the .NET Libraries
        /// for key generation if not possible will use the
        /// BouncyCastle libraries
        /// </summary>
        bool? PreferDotNetKeyGeneration { get; }
    }
}