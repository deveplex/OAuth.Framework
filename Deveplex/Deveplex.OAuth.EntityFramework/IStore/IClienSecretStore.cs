using Microsoft.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.OAuth.Framework
{
    public interface IClientStore<TApp> : IClientStore<TApp, string>, IUserStore<TApp>
        where TApp : class, IUser
    {
    }

    public interface IClientStore<TApp, in TKey> : IUserStore<TApp, TKey>, IDisposable
        where TApp : class, IUser<TKey>
    {
        Task<IList<TApp>> GetClientsAsync(TKey OwnerId);
    }
}
