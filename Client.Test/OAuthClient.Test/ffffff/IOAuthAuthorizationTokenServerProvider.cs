using Microsoft.Owin.Security.Provider;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.OAuth
{
    /// <summary>
    /// Specifies callback methods which the <see cref="WeChatAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IOAuthAuthorizationTokenServerProvider
    {
        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        Task Authenticated(OAuthAuthenticatedTokenContext context);
    }
}