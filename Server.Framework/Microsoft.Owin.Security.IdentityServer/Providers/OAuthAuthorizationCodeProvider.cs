using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.IdentityServer
{
    public class IdentityAuthorizationCodeProvider : OAuthAuthenticationTokenProvider
    {
        private readonly ConcurrentDictionary<string, string> _authenticationCodes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        public IdentityAuthorizationCodeProvider()
        {
        }

        public override async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            await base.CreateAsync(context);
            if (context.Token == null)
            {
                context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            }
            _authenticationCodes[context.Token] = context.SerializeTicket();
        }

        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            string value;
            if (_authenticationCodes.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }
            await base.ReceiveAsync(context);
        }

        /// <summary>
        /// 生成 authorization_code
        /// </summary>
        public override void Create(AuthenticationTokenCreateContext context)
        {
        }

        /// <summary>
        /// 由 authorization_code 解析成 access_token
        /// </summary>
        public override void Receive(AuthenticationTokenReceiveContext context)
        {
        }
    }
}