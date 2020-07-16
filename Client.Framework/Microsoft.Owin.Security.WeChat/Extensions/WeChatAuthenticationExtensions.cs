using System;
using Microsoft.Owin.Security.WeChat;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="WeChatAuthenticationMiddleware"/>
    /// </summary>
    public static class WeChatAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Weixin
        /// </summary>
        public static IAppBuilder UseWeChatAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return UseWeChatAuthentication(app, new WeChatAuthenticationOptions() { AppId = appId, AppSecret = appSecret });
        }

        /// <summary>
        /// Authenticate users using Weixin
        /// </summary>
        public static IAppBuilder UseWeChatAuthentication(this IAppBuilder app, WeChatAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(WeChatAuthenticationMiddleware), app, options);
            return app;
        }
    }
}