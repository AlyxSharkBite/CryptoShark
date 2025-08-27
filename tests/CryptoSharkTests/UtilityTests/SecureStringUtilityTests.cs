using CryptoShark.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.UtilityTests
{
    public class SecureStringUtilityTests
    {
        private char[] _password = new char[] { 'A', 'b', 'c', '1', '2', '3' };

        [Test]
        public void SecureStringTest()
        {
            SecureStringUtilities secureStringUtilities = new SecureStringUtilities();
            var securePassword = secureStringUtilities.StringToSecureString(_password);

            var password = secureStringUtilities.SecureStringToCharArray(securePassword);
            Assert.That(password.Length, Is.GreaterThan(0));
            Assert.That(password.SequenceEqual(_password), Is.True);
        }      

    }
}
