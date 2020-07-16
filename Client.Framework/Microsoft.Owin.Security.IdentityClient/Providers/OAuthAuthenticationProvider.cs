using Microsoft.Owin.Security.Provider;
using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.IdentityClient
{
    /// <summary>
    /// Default Authentication Provider<see cref="IOAuthAuthenticationProvider"/> implementation.
    /// </summary>
    public class OAuthAuthenticationProvider : IOAuthAuthenticationProvider
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<OAuthAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<OAuthReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        ///// <summary>
        ///// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        ///// </summary>
        public Action<OAuthApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        ///
        /// </summary>
        public OAuthAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        public Task Authenticated(OAuthAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        public Task ReturnEndpoint(OAuthReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint
        /// </summary>
        public void ApplyRedirect(OAuthApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}