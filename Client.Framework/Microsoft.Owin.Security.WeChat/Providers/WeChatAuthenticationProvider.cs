using Microsoft.Owin.Security.Provider;
using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.WeChat
{
    /// <summary>
    /// Default <see cref="IWeChatAuthenticationProvider"/> implementation.
    /// </summary>
    public class WeChatAuthenticationProvider : IWeChatAuthenticationProvider
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<WeChatAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<WeChatReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        ///// <summary>
        ///// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        ///// </summary>
        public Action<WeChatApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        ///
        /// </summary>
        public WeChatAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        public Task Authenticated(WeChatAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        public Task ReturnEndpoint(WeChatReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint
        /// </summary>
        public void ApplyRedirect(WeChatApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}