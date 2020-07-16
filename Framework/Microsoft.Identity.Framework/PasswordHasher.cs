using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity
{
    internal class PasswordHasher : IPasswordHasher
    {
        public virtual string HashPassword(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            return password;
        }
    }
}
