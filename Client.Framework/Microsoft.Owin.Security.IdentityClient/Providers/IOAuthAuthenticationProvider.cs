using Microsoft.Owin.Security.Provider;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.IdentityClient
{
    /// <summary>
    /// Specifies callback methods which the <see cref="OAuthAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IOAuthAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        Task Authenticated(OAuthAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        Task ReturnEndpoint(OAuthReturnEndpointContext context);

        ///// <summary>
        ///// Called when a Challenge causes a redirect to authorize endpoint in the Microsoft middleware
        ///// </summary>
        void ApplyRedirect(OAuthApplyRedirectContext context);
    }
}