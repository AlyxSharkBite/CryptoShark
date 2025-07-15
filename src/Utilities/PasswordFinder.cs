using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Utilities
{
    internal class PasswordFinder(SecureString password) : IPasswordFinder
    {
        private readonly SecureStringUtilities secureStringUtilities = new SecureStringUtilities();

        public char[] GetPassword()
        {
            return secureStringUtilities.SecureStringToCharArray(password);
        }
    }
}
