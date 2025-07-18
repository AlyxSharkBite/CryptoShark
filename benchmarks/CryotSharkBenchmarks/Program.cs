using BenchmarkDotNet.Running;
using System.Security.Cryptography;

namespace CryotSharkBenchmarks
{
    internal class Program
    {
        static void Main(string[] args)
        {
            /*
             * Security (In Bits)	RSA Key Length Required (In Bits)	ECC Key Length Required (In Bits)
               80	                1024	                            160  brainpoolP160r1
               112	                2048	                            224  brainpoolP224r1
               128	                3072	                            256  brainpoolP256r1
               156                  4096                                312  brainpoolP320r1
               192	                7680	                            384  brainpoolP384r1
               256	                15360	                            512+ brainpoolP512r1
            */

            var summary = BenchmarkRunner.Run<KeyGenerationBenchmark>();
        }
    }
}
