// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;

namespace Microsoft.Owin.Security.OAuth
{
    /// <summary>
    /// Authorization Server middleware component which is added to an OWIN pipeline. This class is not
    /// created by application code directly, instead it is added by calling the the IAppBuilder UseOAuthAuthorizationServer 
    /// extension method.
    /// </summary>
    public class OAuthAuthorizationTokenServerMiddleware : AuthenticationMiddleware<OAuthAuthorizationTokenServerOptions>
    {
        private readonly ILogger _logger;

        /// <summary>
        /// Authorization Server middleware component which is added to an OWIN pipeline. This constructor is not
        /// called by application code directly, instead it is added by calling the the IAppBuilder UseOAuthAuthorizationServer 
        /// extension method.
        /// </summary>
        public OAuthAuthorizationTokenServerMiddleware(OwinMiddleware next, IAppBuilder app, OAuthAuthorizationTokenServerOptions options)
            : base(next, options)
        {
            _logger = app.CreateLogger<OAuthAuthorizationTokenServerMiddleware>();

            if (String.IsNullOrEmpty(Options.CookieName))
            {
                Options.CookieName = CookieAuthenticationDefaults.CookiePrefix + Options.AuthenticationType;
            }
            if (Options.CookieDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(CookieAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");

                Options.CookieDataFormat = new TicketDataFormat(dataProtector);
            }
            if (Options.AccessTokenFormat == null)
            {
                IDataProtector dataProtecter = app.CreateDataProtector(
                typeof(OAuthAuthorizationTokenServerMiddleware).Namespace,
                "Access_Token", "v1");
                Options.AccessTokenFormat = new TicketDataFormat(dataProtecter);
            }
            if (Options.RefreshTokenFormat == null)
            {
                IDataProtector dataProtecter = app.CreateDataProtector(
                typeof(OAuthAuthorizationTokenServerMiddleware).Namespace,
                "Refresh_Token", "v1");
                Options.RefreshTokenFormat = new TicketDataFormat(dataProtecter);
            }
            if (Options.AccessTokenProvider == null)
            {
                Options.AccessTokenProvider = new AuthenticationTokenProvider();
            }
            if (Options.RefreshTokenProvider == null)
            {
                Options.RefreshTokenProvider = new AuthenticationTokenProvider();
            }
            if (Options.CookieManager == null)
            {
                Options.CookieManager = new ChunkingCookieManager();
            }
        }

        /// <summary>
        /// Called by the AuthenticationMiddleware base class to create a per-request handler. 
        /// </summary>
        /// <returns>A new instance of the request handler</returns>
        protected override AuthenticationHandler<OAuthAuthorizationTokenServerOptions> CreateHandler()
        {
            return new OAuthAuthorizationTokenServerHandler(_logger);
        }
    }
}