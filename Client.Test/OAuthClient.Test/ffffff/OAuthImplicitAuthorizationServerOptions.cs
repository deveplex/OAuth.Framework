// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;

namespace Microsoft.Owin.Security.OAuth
{
    /// <summary>
    /// Options class provides information needed to control Authorization Server middleware behavior
    /// </summary>
    public class OAuthImplicitAuthorizationServerOptions : AuthenticationOptions
    {
        /// <summary>
        /// Creates an instance of authorization server options with default values.
        /// </summary>
        public OAuthImplicitAuthorizationServerOptions()
            : base(OAuthDefaults.AuthenticationType)
        {
            AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(20);
            RefreshTokenExpireTimeSpan = TimeSpan.FromHours(2);
            SystemClock = new SystemClock();
        }

        /// <summary>
        /// The data format used to protect the information contained in the access token. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection. If a different access token
        /// provider or format is assigned, a compatible instance must be assigned to the OAuthBearerAuthenticationOptions.AccessTokenProvider 
        /// or OAuthBearerAuthenticationOptions.AccessTokenFormat property of the resource server.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        /// <summary>
        /// The data format used to protect and unprotect the information contained in the refresh token. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> RefreshTokenFormat { get; set; }

        /// <summary>
        /// </summary>
        public TimeSpan RefreshTokenExpireTimeSpan { get; set; }

        /// <summary>
        /// The period of time the access token remains valid after being issued. The default is twenty minutes.
        /// The client application is expected to refresh or acquire a new access token after the token has expired. 
        /// </summary>
        public TimeSpan AccessTokenExpireTimeSpan { get; set; }

        /// <summary>
        /// Produces a bearer token the client application will typically be providing to resource server as the authorization bearer 
        /// http request header. If not provided the token produced on the server's default data protection. If a different access token
        /// provider or format is assigned, a compatible instance must be assigned to the OAuthBearerAuthenticationOptions.AccessTokenProvider 
        /// or OAuthBearerAuthenticationOptions.AccessTokenFormat property of the resource server.
        /// </summary>
        public IAuthenticationTokenProvider AccessTokenProvider { get; set; }

        /// <summary>
        /// Produces a refresh token which may be used to produce a new access token when needed. If not provided the authorization server will
        /// not return refresh tokens from the /Token endpoint.
        /// </summary>
        public IAuthenticationTokenProvider RefreshTokenProvider { get; set; }

        /// <summary>
        /// Set to true if the web application is able to render error messages on the /Authorize endpoint. This is only needed for cases where
        /// the browser is not redirected back to the client application, for example, when the client_id or redirect_uri are incorrect. The 
        /// /Authorize endpoint should expect to see "oauth.Error", "oauth.ErrorDescription", "oauth.ErrorUri" properties added to the owin environment.
        /// </summary>
        public bool ApplicationCanDisplayErrors { get; set; }

        /// <summary>
        /// Used to know what the current clock time is when calculating or validating token expiration. When not assigned default is based on
        /// DateTimeOffset.UtcNow. This is typically needed only for unit testing.
        /// </summary>
        public ISystemClock SystemClock { get; set; }

        /// <summary>
        /// True to allow authorize and token requests to arrive on http URI addresses, and to allow incoming 
        /// redirect_uri authorize request parameter to have http URI addresses.
        /// </summary>
        public bool AllowInsecureHttp { get; set; }

        /// <summary>
        /// Endpoint responsible for Form Post Response Mode
        /// See also, http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        /// </summary>
        public PathString FormPostEndpoint { get; set; }
    }
}