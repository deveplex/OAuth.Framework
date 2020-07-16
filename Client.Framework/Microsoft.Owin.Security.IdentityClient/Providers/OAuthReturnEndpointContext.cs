using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.IdentityClient
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class OAuthReturnEndpointContext : ReturnEndpointContext
    {
        public OAuthReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
        {
        }
    }
}