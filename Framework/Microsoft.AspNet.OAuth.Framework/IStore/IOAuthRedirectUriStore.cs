using Microsoft.AspNet.Identity;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.Framework
{
    public interface IOAuthRedirectUriStore<TApp, in TKey> : IOAuthStore<TApp, TKey>, IDisposable
        where TApp : class, IClient<TKey>
    {
        Task<string> GetRedirectUriAsync(TApp app);
        Task SetRedirectUriAsync(TApp app, string url);
    }
}
