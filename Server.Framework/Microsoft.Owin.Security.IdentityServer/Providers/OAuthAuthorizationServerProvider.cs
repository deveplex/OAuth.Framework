using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.IdentityServer
{
    public class IdentityAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        //private readonly string ClientAuthenticationKey = "";
        //private readonly string ServerId;
        /// <summary>
        /// The _user manager
        /// </summary>
        //private readonly UserManager _userManager;

        public IdentityAuthorizationServerProvider(/*UserManager userManager*/)
        {
            //_userManager = userManager;
        }

        #region Client ID
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //string clientId;
            //string clientSecret;
            //if (context.TryGetBasicCredentials(out clientId, out clientSecret) || context.TryGetFormCredentials(out clientId, out clientSecret))
            //{
            //    //if (clientId == "1234" && clientSecret == "5678")
            //    //{
            //    //    context.Validated(clientId);
            //    //}
            //}
            //else
            //{
            //    //context.Rejected();
            //}

            await base.ValidateClientAuthentication(context);
        }

        public override async Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            await base.GrantClientCredentials(context);

            var identity = context.Ticket != null ? context.Ticket.Identity : null;
            if (identity != null)
            {
                var properties = context.Ticket.Properties;
                var oauthIdentity = identity;
                if (identity.AuthenticationType != OAuthDefaults.AuthenticationType)
                {
                    oauthIdentity = new ClaimsIdentity(identity.Claims, OAuthDefaults.AuthenticationType);
                }
                System.Reflection.AssemblyName assemblyName = System.Reflection.Assembly.GetExecutingAssembly().GetName();
                oauthIdentity.AddClaim(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/assemblyname", assemblyName.Name.ToString()));
                oauthIdentity.AddClaim(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/assemblyversion", assemblyName.Version.ToString()));
                var ticket = new AuthenticationTicket(oauthIdentity, properties);
                context.Validated(ticket);
            }
        }
        #endregion Client ID

        #region Password
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });
            //var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            //ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);

            //if (user == null)
            //{
            //    context.SetError("invalid_grant", "用户名或密码不正确。");
            //    return;
            //}
            //if (context.OwinContext.Authentication.User.Identity.IsAuthenticated)
            //{
            //    var oAuthClaims = context.OwinContext.Authentication.User.Claims;
            //    var claim = oAuthClaims.SingleOrDefault(c => c.Type == ClaimTypes.Authentication && c.Value=="");
            //    foreach (var c in oAuthClaims)
            //    {
            //        oAuthIdentity.AddClaim(c);
            //    }
            //    var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            //    oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));

            //    //AuthenticationProperties properties = CreateProperties(user.UserName);
            //    var ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());
            //    context.Validated(ticket);
            //}

            await base.GrantResourceOwnerCredentials(context);
        }
        #endregion Password

        public override async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        {
            //if (context.AuthorizeRequest.IsImplicitGrantType)
            //{
            //    //    //implicit 授权方式
            //    //    var identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
            //    //    context.OwinContext.Authentication.SignIn(identity);
            //    //    context.RequestCompleted();
            //}
            //else if (context.AuthorizeRequest.IsAuthorizationCodeGrantType)
            //{
            //    //authorization code 授权方式
            //    //var ticket = new AuthenticationTicket(
            //    //        identity,
            //    //        new AuthenticationProperties(new Dictionary<string, string>
            //    //        {
            //    //            {"client_id", clientId},
            //    //            {"redirect_uri", redirectUri}
            //    //        })
            //    //        {
            //    //            IssuedUtc = DateTimeOffset.UtcNow,
            //    //            ExpiresUtc = DateTimeOffset.UtcNow.Add(context.Options.AuthorizationCodeExpireTimeSpan)
            //    //        });
            //}

            await base.AuthorizeEndpoint(context);
        }

        public override async Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {

            await base.ValidateClientRedirectUri(context);
        }

        public override async Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            //if (/*context.Request.Uri == "xishuai" &&*/
            //            (context.AuthorizeRequest.IsAuthorizationCodeGrantType || context.AuthorizeRequest.IsImplicitGrantType))
            //{
            //context.Validated();
            //}
            //else
            //{
            //    context.Rejected();
            //}

            await base.ValidateAuthorizeRequest(context);
        }

        public override async Task ValidateTokenRequest(OAuthValidateTokenRequestContext context)
        {
            //if (context.TokenRequest.IsAuthorizationCodeGrantType || context.TokenRequest.IsRefreshTokenGrantType)
            //{
            //    context.Validated();
            //}
            //else
            //{
            //    context.Rejected();
            //}

            await base.ValidateTokenRequest(context);
        }

        public override async Task MatchEndpoint(OAuthMatchEndpointContext context)
        {
            if (!context.Request.QueryString.HasValue)
            {
                context.RequestCompleted();
                return;
            }

            var appid = context.QueryString.SingleOrDefault(k => k.Key.ToLower() == "appid");//context.Request.Query.SingleOrDefault(k => k.Key.ToLower() == "appid");
            if (appid.Value != null && appid.Value.Length > 0)
            {
                context.QueryString.Add("client_id", appid.Value);
            }

            var appsecret = context.QueryString.SingleOrDefault(k => k.Key.ToLower() == "appsecret");//context.Request.Query.SingleOrDefault(k => k.Key.ToLower() == "appsecret");
            if (appsecret.Value != null && appsecret.Value.Length > 0)
            {
                context.QueryString.Add("client_secret", appsecret.Value);
            }

            await base.MatchEndpoint(context);
        }
    }
}