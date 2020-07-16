using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.IdentityServer
{
    public class IdentityRefreshTokenProvider : OAuthAuthenticationTokenProvider
    {
        private static ConcurrentDictionary<string, string> _refreshTokens = new ConcurrentDictionary<string, string>();
        public IdentityRefreshTokenProvider(/*ITokenStore<IToken> store*/)
        {
        }

        public override async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            await base.CreateAsync(context);
            if (context.Token == null)
            {
                //var token = await _TokenStore.CreateAsync();
                //if (token == null)
                //{
                //    return;
                //}

                //context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
                //context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

                context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            }
            _refreshTokens[context.Token] = context.SerializeTicket();
        }
        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            string value;
            if (_refreshTokens.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }
            await base.ReceiveAsync(context);
        }

        /// <summary>
        /// 生成 refresh_token
        /// </summary>
        public override void Create(AuthenticationTokenCreateContext context)
        {
        }

        /// <summary>
        /// 由 refresh_token 解析成 access_token
        /// </summary>
        public override void Receive(AuthenticationTokenReceiveContext context)
        {
        }
    }
}