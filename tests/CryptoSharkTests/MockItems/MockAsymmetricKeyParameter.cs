using CryptoShark.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.MockItems
{
    public class MockAsymmetricKeyParameter : IAsymmetricKeyParameter
    {
        public SecureString Password => throw new NotImplementedException();
    }
}
