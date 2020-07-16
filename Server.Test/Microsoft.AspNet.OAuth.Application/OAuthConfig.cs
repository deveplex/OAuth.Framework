using Deveplex.OAuth;
using Deveplex.OAuth.EntityFramework;
using Deveplex.OAuth.Framework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Identity;
using Microsoft.Owin;

namespace Microsoft.AspNet.OAuth.Application
{
    public class ApplicationClientManager : ClientManager<Client>
    {
        public ApplicationClientManager(IUserStore<Client> store)
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
