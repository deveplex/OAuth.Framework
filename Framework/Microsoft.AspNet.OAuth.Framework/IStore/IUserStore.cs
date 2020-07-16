using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.Framework
{
    public interface IOAuthStore<TApp> : IOAuthStore<TApp, string>, IDisposable
        where TApp : class, IClient<string>
    {
    }

    public interface IOAuthStore<TApp, in TKey> : IDisposable
        where TApp : class, IClient<TKey>
    {
        Task<TApp> FindAsync(string appId);
        Task CreateAsync(TApp app);
        Task UpdateAsync(TApp app);
        Task DeleteAsync(TApp app);
    }
}
