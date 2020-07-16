using Microsoft.AspNet.Identity;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.Framework
{
    public interface IOAuthSecretStore<TApp, in TKey> : IOAuthStore<TApp, TKey>, IDisposable
        where TApp : class, IClient<TKey>
    {
        Task<string> GetSecretAsync(TApp app);
        Task AddSecretAsync(TApp app, string secret);
        Task SetSecretAsync(TApp app, string secret);
        Task<bool> VerifySecretAsync(TApp app, string secret);
        Task<bool> HasSecretAsync(TApp app);
        Task<string> GetHashKeyAsync(TApp user);
    }
}
