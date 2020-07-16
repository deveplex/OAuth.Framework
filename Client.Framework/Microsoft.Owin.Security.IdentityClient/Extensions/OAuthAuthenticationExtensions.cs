using System;
using Microsoft.Owin.Security.IdentityClient;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="OAuthAuthenticationMiddleware"/>
    /// </summary>
    public static class OAuthAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Open Identity
        /// </summary>
        public static IAppBuilder UseOAuthAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return UseOAuthAuthentication(app, new OAuthAuthenticationOptions() { AppId = appId, AppSecret = appSecret });
        }

        /// <summary>
        /// Authenticate users using Open Identity
        /// </summary>
        public static IAppBuilder UseOAuthAuthentication(this IAppBuilder app, OAuthAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(OAuthAuthenticationMiddleware), app, options);
            return app;
        }
    }
}