using Deveplex.OAuth;
using Deveplex.OAuth.EntityFramework;
using Deveplex.OAuth.Framework;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;

namespace Microsoft.AspNet.OpenPlatform.Application
{
    public class ApplicationClientManager : ClientManager<Client>
    {
        public ApplicationClientManager(ClientStore<Client> store)
            : base(store)
        {
        }

        public static ApplicationClientManager Create(IdentityFactoryOptions<ApplicationClientManager> options, IOwinContext context)
        {
            var manager = new ApplicationClientManager(new ClientStore<Client>(context.Get<ClientDbContext>()));

            return manager;
        }
    }

    public class ClientDbContext : OAuthDbContext
    {
        public ClientDbContext()
            : base("OAuthConnection")
        {
        }

        public static ClientDbContext Create(IdentityFactoryOptions<ClientDbContext> options, IOwinContext context)
        {
            var dbcontext = new ClientDbContext();

            return dbcontext;
        }

    }
}
