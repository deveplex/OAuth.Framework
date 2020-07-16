using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.WeChat
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class WeChatReturnEndpointContext : ReturnEndpointContext
    {
        public WeChatReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
        {
        }
    }
}