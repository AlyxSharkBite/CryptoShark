using CryptoShark.Enums;
using CryptoShark.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Configuration
{
    public class CryptoSharkConfiguration : ICryptoSharkConfiguration
    {
        public EncryptionAlgorithm? DefaultEncryptionAlgorithm { get; set; }
        public HashAlgorithm? DefaultHashAlgorithm { get; set; }
        public RsaKeySize? DefaultRsaKeySize { get; set; }
        public bool? CompressBeforeEncryption { get; set; }
        public bool? PreferDotNetKeyGeneration { get; set; }
        public string DefaultRsaPadding { get; set; }
        public string DefaultEccCurveOid { get; set; }
    }
}
