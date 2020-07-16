using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.Framework
{
    public interface IUserSecurityStampStore<TApp, in TKey> : IOAuthStore<TApp, TKey>, IDisposable where TApp : class, IClient<TKey>
    {
        Task<string> GetSecurityStampAsync(TApp app);
        Task SetSecurityStampAsync(TApp app, string stamp);
    }
}
