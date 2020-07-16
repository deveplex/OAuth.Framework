using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.Framework
{
    public interface IOAuthScopeStore<TApp, TKey> : IOAuthStore<TApp, TKey>, IDisposable
        where TApp : class, IClient<TKey>
    {
        Task AddScopeAsync(TApp app, string scope);
        Task<IEnumerable<KeyValuePair<TKey, string>>> GetScopeAsync(TApp app);
        Task<bool> IsInScopeAsync(TApp app, string scope);
        Task RemoveScopeAsync(TApp app, string scope);
    }
}
