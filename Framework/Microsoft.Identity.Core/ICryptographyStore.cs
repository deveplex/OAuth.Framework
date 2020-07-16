using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity
{
    public interface ICryptographyStore<TUser> : ICryptographyStore<TUser, string>
    {
    }

    public interface ICryptographyStore<TUser, in TKey>
    {
    }
}
