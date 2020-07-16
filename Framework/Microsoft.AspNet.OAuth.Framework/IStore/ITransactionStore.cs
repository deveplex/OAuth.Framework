using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.Framework
{
    public interface ITransactionStore<TApp, in TKey> : IOAuthStore<TApp, TKey>, IDisposable
        where TApp : class, IClient<TKey>
    {
        Task CommitChangesAsync();
    }
}
