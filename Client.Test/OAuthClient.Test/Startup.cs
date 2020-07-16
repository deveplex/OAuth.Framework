using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Application;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.IdentityClient;
using Microsoft.Owin.Security.QQ;
using Microsoft.Owin.Security.WeChat;
using Owin;

[assembly: OwinStartup(typeof(OAuthClient.Test.Startup))]

namespace OAuthClient.Test
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // 有关如何配置应用程序的详细信息，请访问 https://go.microsoft.com/fwlink/?LinkID=316888
            ConfigureServices(app);
        }

        // 有关配置身份验证的详细信息，请访问 http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureServices(IAppBuilder app)
        {
            // 配置数据库上下文、用户管理器和登录管理器，以便为每个请求使用单个实例
            app.CreatePerOwinContext<ApplicationDbContext>(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);
            app.CreatePerOwinContext<ApplicationRoleManager>(ApplicationRoleManager.Create);

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
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // 使应用程序可以在双重身份验证过程中验证第二因素时暂时存储用户信息。
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // 使应用程序可以记住第二登录验证因素，例如电话或电子邮件。
            // 选中此选项后，登录过程中执行的第二个验证步骤将保存到你登录时所在的设备上。
            // 此选项类似于在登录时提供的“记住我”选项。
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            //app.UseOAuthAuthorizationTokenServer(new OAuthAuthorizationTokenServerOptions {
            //    Provider=new OAuthAuthorizationTokenServerProvider
            //    {
            //        OnAuthenticated= OnAuthenticated
            //    }
            //});

            // 取消注释以下行可允许使用第三方登录提供程序登录
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            //{
            //    ClientId = "",
            //    ClientSecret = ""
            //});


            //app.UseOAuthAuthentication("wxd4f6cbe87fe2e377", "dffc7a172b5a6e1c433f680eb612738c");
            //app.UseOAuthAuthentication(new OAuthAuthenticationOptions
            //{
            //    AppId = "wxd4f6cbe87fe2e377",
            //    AppSecret = "dffc7a172b5a6e1c433f680eb612738c",
            //});

            //app.UseQQAuthentication("wxd4f6cbe87fe2e377", "dffc7a172b5a6e1c433f680eb612738c");
            app.UseQQAuthentication(new QQAuthenticationOptions
            {
                AppId = "wxd4f6cbe87fe2e377",
                AppSecret = "dffc7a172b5a6e1c433f680eb612738c",
            });

            //app.UseWeChatAuthentication("wxd4f6cbe87fe2e377", "dffc7a172b5a6e1c433f680eb612738c");
            app.UseWeChatAuthentication(new WeChatAuthenticationOptions
            {
                AppId = "wxd4f6cbe87fe2e377",
                AppSecret = "dffc7a172b5a6e1c433f680eb612738c",
                Scope = new List<string> { "snsapi_userinfo" }
            });

        }

        //private Task OnAuthenticated(OAuthAuthenticatedTokenContext context)
        //{
        //    return Task.FromResult(0);
        //}
    }
}
