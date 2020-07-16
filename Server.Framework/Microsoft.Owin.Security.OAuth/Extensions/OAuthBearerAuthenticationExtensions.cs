// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace Owin
{
    /// <summary>
    /// Extension methods to add OAuth Bearer authentication capabilities to an OWIN application pipeline
    /// </summary>
    public static class OAuthBearerAuthenticationExtensions
    {
        /// <summary>
        /// Adds Bearer token processing to an OWIN application pipeline. This middleware understands appropriately
        /// formatted and secured tokens which appear in the request header. If the Options.AuthenticationMode is Active, the
        /// claims within the bearer token are added to the current request's IPrincipal User. If the Options.AuthenticationMode 
        /// is Passive, then the current request is not modified, but IAuthenticationManager AuthenticateAsync may be used at
        /// any time to obtain the claims from the request's bearer token.
        /// See also http://tools.ietf.org/html/rfc6749
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="options">Options which control the processing of the bearer header.</param>
        /// <returns>The application builder</returns>
        public static IAppBuilder UseOAuthBearerAuthentication(this IAppBuilder app, OAuthBearerAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            app.Use(typeof(OAuthBearerAuthenticationMiddleware), app, options);
            app.UseStageMarker(PipelineStage.Authenticate);
            return app;
        }

        /// <summary>
        ///     Configure the app to use owin middleware based oauth bearer tokens
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options"></param>
        [SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth", Justification = "By Design")]
        public static void UseOAuthBearerTokens(this IAppBuilder app, OAuthAuthorizationServerOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.UseOAuthAuthorizationServer(options);

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AccessTokenFormat = options.AccessTokenFormat,
                AccessTokenProvider = options.AccessTokenProvider,
                AuthenticationMode = options.AuthenticationMode,
                AuthenticationType = options.AuthenticationType,
                Description = options.Description,
                Provider = new ApplicationOAuthBearerProvider(),
                SystemClock = options.SystemClock
            });

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AccessTokenFormat = options.AccessTokenFormat,
                AccessTokenProvider = options.AccessTokenProvider,
                AuthenticationMode = AuthenticationMode.Passive,
                AuthenticationType = "ExternalBearer",//DefaultAuthenticationTypes.ExternalBearer,
                Description = options.Description,
                Provider = new ExternalOAuthBearerProvider(),
                SystemClock = options.SystemClock
            });
        }

        private class ApplicationOAuthBearerProvider : OAuthBearerAuthenticationProvider
        {
            public override Task ValidateIdentity(OAuthValidateIdentityContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }
                if (context.Ticket.Identity.Claims.Any(c => c.Issuer != ClaimsIdentity.DefaultIssuer))
                {
                    context.Rejected();
                }
                return Task.FromResult<object>(null);
            }
        }

        private class ExternalOAuthBearerProvider : OAuthBearerAuthenticationProvider
        {
            public override Task ValidateIdentity(OAuthValidateIdentityContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }
                if (context.Ticket.Identity.Claims.Count() == 0)
                {
                    context.Rejected();
                }
                else if (context.Ticket.Identity.Claims.All(c => c.Issuer == ClaimsIdentity.DefaultIssuer))
                {
                    context.Rejected();
                }

                return Task.FromResult<object>(null);
            }
        }
    }
}
