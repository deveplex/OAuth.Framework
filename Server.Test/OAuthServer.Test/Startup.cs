using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.Application;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.OAuth.Application;
using Microsoft.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.IdentityServer;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;

[assembly: OwinStartup(typeof(OAuthServer.Test.Startup))]

namespace OAuthServer.Test
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // 有关如何配置应用程序的详细信息，请访问 https://go.microsoft.com/fwlink/?LinkID=316888
            ConfigureServices(app);

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
        }

        // 有关配置身份验证的详细信息，请访问 http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureServices(IAppBuilder app)
        {
            // 配置数据库上下文、用户管理器和登录管理器，以便为每个请求使用单个实例
            app.CreatePerOwinContext<ApplicationDbContext>(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);
            //app.CreatePerOwinContext<ApplicationRoleManager>(ApplicationRoleManager.Create);
            app.CreatePerOwinContext<ClientDbContext>(ClientDbContext.Create);
            app.CreatePerOwinContext<ApplicationClientManager>(ApplicationClientManager.Create);

            // 使应用程序可以使用 Cookie 来存储已登录用户的信息
            // 并使用 Cookie 来临时存储有关使用第三方登录提供程序登录的用户的信息
            // 配置登录 Cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                LogoutPath = new PathString("/Account/Logoff"),
                //Provider = new CookieAuthenticationProvider
                //{
                //    // 当用户登录时使应用程序可以验证安全戳。
                //    // 这是一项安全功能，当你更改密码或者向帐户添加外部登录名时，将使用此功能。
                //    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                //        validateInterval: TimeSpan.FromMinutes(30),
                //        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                //}
            });

            // 使应用程序可以在双重身份验证过程中验证第二因素时暂时存储用户信息。
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // 使应用程序可以记住第二登录验证因素，例如电话或电子邮件。
            // 选中此选项后，登录过程中执行的第二个验证步骤将保存到你登录时所在的设备上。
            // 此选项类似于在登录时提供的“记住我”选项。
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // 使应用程序可以使用不记名令牌来验证用户身份
            app.UseOAuthAuthorizationServer(new IdentityAuthorizationServerOptions
            {
                //AuthenticationType = OAuthDefaults.AuthenticationType,
                //LoginPath = new PathString("/Account/Login"),
                //LogoutPath = new PathString("/Account/Logoff"),
                ApplicationCanDisplayErrors = false,
#if DEBUG
                AllowInsecureHttp = true,
#endif
                // Authorization server provider which controls the lifecycle of Authorization Server
                Provider = new IdentityAuthorizationServerProvider()
                {
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,
                    OnValidateAuthorizeRequest = ValidateAuthorizeRequest,
                    OnValidateClientAuthentication = ValidateClientAuthentication,
                    OnGrantResourceOwnerCredentials = GrantResourceOwnerCredentials,
                    OnAuthorizeEndpoint = AuthorizeEndpoint,
                    OnGrantClientCredentials = GrantClientCredetails
                },

                // Authorization code provider which creates and receives the authorization code.
                AuthorizationCodeProvider = new IdentityAuthorizationCodeProvider()
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode,
                },

                //Refresh token provider which creates and receives refresh token.
                RefreshTokenProvider = new IdentityRefreshTokenProvider()
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken,
                }
            });
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }

        private async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        {
            await Task.FromResult(0);

        }

        private async Task GrantClientCredetails(OAuthGrantClientCredentialsContext context)
        {
            var authenticationManager = context.OwinContext.Authentication;
            var authenticateResult = await authenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie);
            context.Validated(new AuthenticationTicket(authenticateResult.Identity, authenticateResult.Properties));
        }

        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
        }

        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
        }

        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
        }

        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
        }

        private async Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            var clientManager = context.OwinContext.Get<ApplicationClientManager>();
            var clientScopes = await clientManager.GetUserRolesAsync(context.AuthorizeRequest.ClientId);

            var oauthScopes = new List<dynamic> { new { scope = "scope_base", order = 0 }, new { scope = "scope_userinfo", order = 0 } };
            var scopes = context.AuthorizeRequest.Scope;
            var isInScopes = scopes.Any(s =>
            {
                return oauthScopes.Any(w => w.order > 0 && w.scope.Equals(s, StringComparison.OrdinalIgnoreCase));
            });
            if (!isInScopes)
            {
                context.ClientContext.Rejected();
                context.Rejected();
                context.SetError("invalid_scope", "Invalid Scope");
                return;
            }
            context.Validated();
            await Task.FromResult(0);
        }

        private async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();
            var user = await userManager.FindAsync(context.UserName, context.Password);
            if (user == null)
            {
                context.Rejected();
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }
            await Task.FromResult(0);
        }

        private async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;
            if (context.TryGetBasicCredentials(out clientId, out clientSecret) || context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                var clientManager = context.OwinContext.Get<ApplicationClientManager>();
                var client = await clientManager.FindAsync(clientId, clientSecret);
                if (client != null)
                {
                    context.Validated(clientId);
                }
                else
                {
                    context.Rejected();
                    context.SetError("invalid_client", "Invalid Client");
                }
            }
            else
            {
                context.Rejected();
                context.SetError("invalid_client", "Invalid Client");
            }
        }

        private async Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            var clientManager = context.OwinContext.Get<ApplicationClientManager>();
            var client = await clientManager.FindByNameAsync(context.ClientId);
            if (client == null)
            {
                context.Rejected();
                context.SetError("invalid_client", "Invalid Client");
                return;
            }

            Uri authenticationUri = new Uri(client.CallbackUrl);
            Uri redirectUri = new Uri(context.RedirectUri);
            if (authenticationUri.Host.Equals(redirectUri.Host))
            {
                context.Validated(context.RedirectUri);
            }
            else
            {
                context.Rejected();
                context.SetError("invalid_redirecturi", "Invalid RedirectUri");
            }
        }
    }
}