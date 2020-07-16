using Microsoft.Owin.Security.Provider;
using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.OAuth
{
    /// <summary>
    /// Default <see cref="IWeChatAuthenticationProvider"/> implementation.
    /// </summary>
    public class OAuthAuthorizationTokenServerProvider : IOAuthAuthorizationTokenServerProvider
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<OAuthAuthenticatedTokenContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        ///
        /// </summary>
        public OAuthAuthorizationTokenServerProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        public Task Authenticated(OAuthAuthenticatedTokenContext context)
        {
            return OnAuthenticated(context);
        }
    }
}