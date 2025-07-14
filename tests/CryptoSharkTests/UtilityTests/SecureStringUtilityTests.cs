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
        private string _password = "Abc123";

        [Test]
        public void SecureStringTest()
        {
            SecureStringUtilities secureStringUtilities = new SecureStringUtilities();
            var securePassword = secureStringUtilities.StringToSecureString(_password);

            var password = secureStringUtilities.SecureStringToString(securePassword);
            Assert.That(String.IsNullOrEmpty(password), Is.False);
            Assert.That(String.Equals(password, _password), Is.True);
        }      

    }
}
