using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoShark;
using CryptoShark.Configuration;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Options;
using CryptoShark.Requests;
using Microsoft.VSDiagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryotSharkBenchmarks
{
    public class EccBrainpoolKeyGenerationBenchmark
    {
        private ICryptoSharkCryptographyUtilities _utilities;
        private CryptoSharkConfiguration _configuration = new CryptoSharkConfiguration
        {
            PreferDotNetKeyGeneration = false
        };

        [Params("brainpoolP160r1",
        "brainpoolP224r1",
        "brainpoolP256r1",
        "brainpoolP320r1",
        "brainpoolP384r1",
        "brainpoolP512r1")]
        public string CurveName { get; set; }

        public EccBrainpoolKeyGenerationBenchmark()
        {
            _utilities = CryptoSharkFactory
                  .CreateCryptoSharkFactory(_configuration)
                  .CreateCryptographyUtilities();
        }

        [Benchmark]
        public byte[] CreateEccKey()
        {
            using var keyParams = new EccKeyParameters(
                 typeof(EccNistKeyGenerationBenchmark).Name,
                 ECCurve.CreateFromFriendlyName(CurveName));

            var key = _utilities.CreateAsymetricKey(keyParams)
                .ToArray();

            return key;
        }
    }
}
