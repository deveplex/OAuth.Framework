using Deveplex.OAuth.Framework;
using Microsoft.Identity;
using Microsoft.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.OAuth.EntityFramework
{
    public class ClientStore<TApp> : ClientStore<TApp, string, Scope, ClientScope>
        , IClientStore<TApp>
        , IUserStore<TApp>
        //, IQueryableUserStore<TUser>
        where TApp : Client, new()
    {
        public ClientStore(DbContext context)
            : base(context)
        {
        }
    }

    public class ClientStore<TApp, TKey, TScope, TClientScope> : UserStore<TApp, TKey, TScope, TClientScope>
        , IClientStore<TApp, TKey>
        , IUserStore<TApp, TKey>
        //, IQueryableUserStore<TUser>
        where TApp : Client<TKey, TClientScope>, new()
        where TScope : Scope<TKey>, new()
        where TClientScope : ClientScope<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private DbSet<TApp> _AppStore;

        public ClientStore(DbContext context)
            : base(context)
        {
            _AppStore = Context.Set<TApp>();
        }

        public virtual async Task<IList<TApp>> GetClientsAsync(TKey OwnerId)
        {
            ThrowIfDisposed();
            if(OwnerId == null)
            {
                throw new ArgumentNullException("OwnerId");
            }

            var query = from a in _AppStore
                        where a.OwnerId.Equals(OwnerId)
                        select a;
            var apps = await query.ToListAsync().WithCurrentCulture();

            return apps;
        }
    }
}
