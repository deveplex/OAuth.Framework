using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity
{
    public interface ICryptography : ICryptography<string>
    {
    }

    public interface ICryptography<TKey>
    {
        TKey UserId { get; set; }

        string PasswordHash { get; set; }

        string PrivateKey { get; set; }
    }

}
