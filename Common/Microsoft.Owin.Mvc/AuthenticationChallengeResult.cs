using Microsoft.Owin.Security;
using System;
using System.Web;
using System.Web.Mvc;

namespace Microsoft.AspNet.Mvc
{
    public class AuthenticationChallengeResult : HttpUnauthorizedResult
    {
        // 用于在添加外部登录名时提供 XSRF 保护
        private const string _XsrfKey = "XsrfId";

        private string UserData { get; set; }
        private string AuthenticationProvider { get; set; }
        private string RedirectUri { get; set; }

        public AuthenticationChallengeResult(string provider, string redirectUri)
            : this(provider, redirectUri, null)
        {
        }

        public AuthenticationChallengeResult(string provider, string redirectUri, string userData)
        {
            AuthenticationProvider = provider;
            RedirectUri = redirectUri;
            UserData = userData;
        }

        public override void ExecuteResult(ControllerContext context)
        {
            // this line fixed the problem with returing null
            context.RequestContext.HttpContext.Response.SuppressFormsAuthenticationRedirect = true;

            var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
            if (UserData != null)
            {
                properties.Dictionary[_XsrfKey] = UserData;
            }
            context.HttpContext.GetOwinContext().Authentication.Challenge(properties, AuthenticationProvider);
        }
    }
}