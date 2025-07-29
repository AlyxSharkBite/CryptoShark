using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using CryptoShark;
using CryptoShark.Enums;
using CryptoShark.Options;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryotSharkBenchmarks
{   

    internal class Program
    {
        static void Main(string[] args)
        {
           
            BenchmarkSwitcher
                .FromAssembly(typeof(Program).Assembly)
                .Run();
            
            

        }
    }
}
