// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using System.Security.Claims;

namespace Microsoft.Owin.Security.OAuth
{
    internal class OAuthAuthorizationTokenServerHandler : AuthenticationHandler<OAuthImplicitAuthorizationServerOptions>
    {
        private const string SessionIdClaim = "Microsoft.Owin.Security.Cookies-SessionId";

        private readonly ILogger _logger;

        private AuthorizeEndpointRequest _authorizeEndpointRequest;
        private OAuthValidateClientRedirectUriContext _clientContext;
        private IDictionary<string, string[]> _requestEndpointParameters;
        public OAuthAuthorizationTokenServerHandler(ILogger logger)
        {
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationTicket ticket = null;
            try
            {
                string cookie = Options.CookieManager.GetRequestCookie(Context, Options.CookieName);
                if (string.IsNullOrWhiteSpace(cookie))
                {
                    return null;
                }

                ticket = Options.CookieDataFormat.Unprotect(cookie);

                if (ticket == null)
                {
                    _logger.WriteWarning(@"Unprotect ticket failed");
                    return null;
                }

                if (Options.SessionStore != null)
                {
                    Claim claim = ticket.Identity.Claims.FirstOrDefault(c => c.Type.Equals(SessionIdClaim));
                    if (claim == null)
                    {
                        _logger.WriteWarning(@"SessoinId missing");
                        return null;
                    }
                    _sessionKey = claim.Value;
                    ticket = await Options.SessionStore.RetrieveAsync(_sessionKey);
                    if (ticket == null)
                    {
                        _logger.WriteWarning(@"Identity missing in session store");
                        return null;
                    }
                }

                DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
                DateTimeOffset? issuedUtc = ticket.Properties.IssuedUtc;
                DateTimeOffset? expiresUtc = ticket.Properties.ExpiresUtc;

                if (expiresUtc != null && expiresUtc.Value < currentUtc)
                {
                    //if (Options.SessionStore != null)
                    //{
                    //    //await Options.SessionStore.RemoveAsync(_sessionKey);
                    //}
                    return null;
                }

                bool? allowRefresh = ticket.Properties.AllowRefresh;
                if (issuedUtc != null && expiresUtc != null && Options.SlidingExpiration
                    && (!allowRefresh.HasValue || allowRefresh.Value))
                {
                    TimeSpan timeElapsed = currentUtc.Subtract(issuedUtc.Value);
                    TimeSpan timeRemaining = expiresUtc.Value.Subtract(currentUtc);

                    if (timeRemaining < timeElapsed)
                    {
                        _shouldRenew = true;
                        _renewIssuedUtc = currentUtc;
                        TimeSpan timeSpan = expiresUtc.Value.Subtract(issuedUtc.Value);
                        _renewExpiresUtc = currentUtc.Add(timeSpan);
                    }
                }
                ticket.Properties.IssuedUtc = _renewIssuedUtc;
                ticket.Properties.ExpiresUtc = _renewExpiresUtc;

                var identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                identity.AddClaims(ticket.Identity.Claims);

                return new AuthenticationTicket(identity, ticket.Properties);
            }
            catch (Exception ex)
            {
                //CookieExceptionContext exceptionContext = new CookieExceptionContext(Context, Options, CookieExceptionContext.ExceptionLocation.AuthenticateAsync, exception, ticket);
                //Options.Provider.Exception(exceptionContext);
                //if (exceptionContext.Rethrow)
                //{
                //    throw;
                //}
                //return exceptionContext.Ticket;
                return null;
            }
        }

        public override async Task<bool> InvokeAsync()
        {
            _requestEndpointParameters = new Dictionary<string, string[]>();
            var matchRequestContext = new OAuthMatchEndpointContext(Context, Options, _requestEndpointParameters);
            if (Options.AuthorizeEndpointPath.HasValue && Options.AuthorizeEndpointPath == Request.Path)
            {
                IReadableStringCollection requestParameters = Request.Query;
                foreach (var p in requestParameters)
                {
                    matchRequestContext.QueryString.Add(p.Key, p.Value);
                }
                matchRequestContext.MatchesAuthorizeEndpoint();
            }
            else if (Options.TokenEndpointPath.HasValue && Options.TokenEndpointPath == Request.Path)
            {
                IFormCollection requestParameters = await Request.ReadFormAsync();
                foreach (var p in requestParameters)
                {
                    matchRequestContext.QueryString.Add(p.Key, p.Value);
                }
                matchRequestContext.MatchesTokenEndpoint();
            }
            await Options.Provider.MatchEndpoint(matchRequestContext);
            if (matchRequestContext.IsRequestCompleted)
            {
                return true;
            }

            if (matchRequestContext.IsAuthorizeEndpoint || matchRequestContext.IsTokenEndpoint)
            {
                if (!Options.AllowInsecureHttp &&
                    String.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.WriteWarning("Authorization server ignoring http request because AllowInsecureHttp is false.");
                    return false;
                }
                if (matchRequestContext.IsAuthorizeEndpoint)
                {
                    return await InvokeAuthorizeEndpointAsync();
                }
                if (matchRequestContext.IsTokenEndpoint)
                {
                    await InvokeTokenEndpointAsync();
                    return true;
                }
            }
            return false;
        }

        protected override async Task ApplyResponseGrantAsync()
        {
            // only successful results of an authorize request are altered
            if (_clientContext == null ||
                _authorizeEndpointRequest == null ||
                Response.StatusCode != 200)
            {
                return;
            }

            // only apply with signin of matching authentication type
            AuthenticationResponseGrant signin = Helper.LookupSignIn(Options.AuthenticationType);
            if (signin == null)
            {
                return;
            }


            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
            signin.Properties.IssuedUtc = currentUtc;
            signin.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenExpireTimeSpan);

            // associate client_id with access token
            signin.Properties.Dictionary[Constants.Extra.ClientId] = _authorizeEndpointRequest.ClientId;

            var accessTokenContext = new AuthenticationTokenCreateContext(
                                Context,
                                Options.AccessTokenFormat,
                                new AuthenticationTicket(signin.Identity, signin.Properties));

            await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

            string accessToken = accessTokenContext.Token;
            if (string.IsNullOrEmpty(accessToken))
            {
                accessToken = accessTokenContext.SerializeTicket();
            }

            DateTimeOffset? accessTokenExpiresUtc = accessTokenContext.Ticket.Properties.ExpiresUtc;

            var authResponseContext = new OAuthAuthenticatedTokenContext(
                Context,
                accessToken);

            await Options.Provider.Authenticated(authResponseContext);
        }

        private async Task<bool> InvokeTokenEndpointAsync()
        {
            AuthenticationTicket ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                return false;
            }
            //    ticket.Properties.IssuedUtc = _renewIssuedUtc;
            //    ticket.Properties.ExpiresUtc = _renewExpiresUtc;

            //    var accessTokenContext = new AuthenticationTokenCreateContext(
            //    Context,
            //    Options.AccessTokenFormat,
            //    ticket);

            //    await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

            //    string accessToken = accessTokenContext.Token;
            //    if (string.IsNullOrEmpty(accessToken))
            //    {
            //        accessToken = accessTokenContext.SerializeTicket();
            //    }
            //    DateTimeOffset? accessTokenExpiresUtc = ticket.Properties.ExpiresUtc;

            //    if (!Options.AuthenticationType.Equals(OAuthDefaults.AuthenticationType, StringComparison.Ordinal))
            //    {
            //        ClaimsIdentity signInIdentity = accessTokenContext.Ticket.Identity;
            //        signInIdentity = new ClaimsIdentity(signInIdentity.Claims, OAuthDefaults.AuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
            //    }
            return true;
        }
    }
}
