using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.WeChat
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the middleware
    /// </summary>
    public class WeChatApplyRedirectContext : BaseContext<WeChatAuthenticationOptions>
    {
        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Gets the authenticaiton properties of the challenge
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }

        public WeChatApplyRedirectContext(IOwinContext context, WeChatAuthenticationOptions options, AuthenticationProperties properties, string redirectUri) : base(context, options)
        {
            this.RedirectUri = redirectUri;
            this.Properties = Properties;
        }
    }
}