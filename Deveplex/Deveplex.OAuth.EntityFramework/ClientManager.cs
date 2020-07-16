using Microsoft.Identity;
using Microsoft.OAuth.EntityFramework;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.OAuth.Framework
{
    public class ClientManager<TApp> : UserManager<TApp>
        where TApp : Client
    {
        public ClientManager(IUserStore<TApp> store)
            : base(store)
        {
            AppStore = store;
        }

        private IUserStore<TApp> AppStore { get; set; }

        public virtual async Task<IList<TApp>> GetClientsAsync(string OwnerId)
        {
            var store= GetPasswordStore();
            return await store.GetClientsAsync(OwnerId);
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        //IUserPasswordStore methods
        private IClientStore<TApp> GetPasswordStore()
        {
            var cast = Store as IClientStore<TApp>;
            if (cast == null)
            {
                throw new NotSupportedException(R.String.Get("StoreNotIClientStore"));
            }
            return cast;
        }
    }
}
