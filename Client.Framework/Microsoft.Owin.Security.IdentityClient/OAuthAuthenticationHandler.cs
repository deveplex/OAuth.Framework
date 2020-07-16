using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.IdentityClient
{
    /// <summary>
    ///
    /// </summary>
    internal class OAuthAuthenticationHandler : AuthenticationHandler<OAuthAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public OAuthAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        /// <summary>
        /// </summary>
        /// <param name="extra"></param>
        /// <returns></returns>
        private string GenerateStateId(AuthenticationProperties extra)
        {
            string stateId = Guid.NewGuid().ToString("n");
            extra.Dictionary["stateId"] = stateId;
            string key = $"_{Options.AuthenticationType}State_{stateId}";
            string stateValue = Options.StateDataFormat.Protect(extra);
            base.Response.Cookies.Append(key, stateValue, new CookieOptions
            {
                HttpOnly = true,
                Secure = base.Request.IsSecure
            });
            return stateId;
        }

        /// <summary>
        /// </summary>
        /// <param name="stateId"></param>
        /// <param name="extra"></param>
        /// <returns></returns>
        private bool ValidateStateId(string stateId, out AuthenticationProperties extra)
        {
            string key = $"_{Options.AuthenticationType}State_{stateId}";
            string protectedText = Request.Cookies[key];
            bool flag = string.IsNullOrWhiteSpace(protectedText);
            bool result;
            if (flag)
            {
                extra = null;
                result = false;
            }
            else
            {
                extra = Options.StateDataFormat.Unprotect(protectedText);
                bool flag2 = extra == null || !extra.Dictionary.ContainsKey("stateId") || extra.Dictionary["stateId"] != stateId;
                if (flag2)
                {
                    extra = null;
                    result = false;
                }
                else
                {
                    result = true;
                }
            }
            return result;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> codeValues = query.GetValues("code");
                if (codeValues != null && codeValues.Count >= 1)
                {
                    code = codeValues[0];
                }
                IList<string> stateValues = query.GetValues("state");
                if (stateValues != null && stateValues.Count >= 1)
                {
                    state = stateValues[0];
                }

                if (!ValidateStateId(state, out properties))
                {
                    _logger.WriteError("Invalid return state, unable to redirect.");
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var requestContent = new FormUrlEncodedContent(new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("appid", Options.AppId),
                    new KeyValuePair<string, string>("secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                });

                // get access_token
                var response = await _httpClient.PostAsync(Options.TokenEndpoint + "", requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                string oauthTokenResponse = await response.Content.ReadAsStringAsync();

                JObject oauth2Token = ObtainAccessTokenAsync(oauthTokenResponse);
                var accessToken = oauth2Token.Value<string>("access_token");
                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                var scope = oauth2Token.Value<string>("scope");
                var openId = oauth2Token.Value<string>("openid");
                JObject userInfo = JObject.FromObject(new { openid = openId });

                var unionId = oauth2Token.Value<string>("unionid");
                if (!string.IsNullOrWhiteSpace(unionId))
                {
                    userInfo.Add(new { unionid = unionId });
                }

                if (Options.Scope.Contains(OAuthAuthenticationOptions.Scope_UserInfo))
                {
                    response = await _httpClient.GetAsync(Options.UserInfoEndpoint + $"?access_token={Uri.EscapeDataString(accessToken)}&openid={Uri.EscapeDataString(openId)}", Request.CallCancelled);
                    response.EnsureSuccessStatusCode();
                    string userInfoResponse = await response.Content.ReadAsStringAsync();

                    userInfo = ObtainUserInfoAsync(userInfoResponse);
                }

                var context = new OAuthAuthenticatedContext(Context, oauth2Token);
                await Options.Provider.Authenticated(context);

                var identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.NameIdentifier, context.AuthenticationKey, ClaimValueTypes.String, Options.AuthenticationType),
                    new Claim(Constants.ClaimType, userInfo.ToString(), ClaimValueTypes.String, Options.AuthenticationType),
                }, Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                var username = userInfo.Value<string>("nickname");
                if (!string.IsNullOrWhiteSpace(username))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Name, username, ClaimValueTypes.String, Options.AuthenticationType));
                }

                var email = userInfo.Value<string>("email");
                if (!string.IsNullOrWhiteSpace(email))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String, Options.AuthenticationType));
                }

                return new AuthenticationTicket(identity, properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        /// <summary>
        /// 401 Redirect
        /// </summary>
        /// <returns></returns>
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;

                string currentUri = baseUri + Request.Path + Request.QueryString;

                string redirectUri = baseUri + Options.RedirectPath;

                AuthenticationProperties extra = challenge.Properties;
                if (string.IsNullOrEmpty(extra.RedirectUri))
                {
                    extra.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(extra);

                string state = GenerateStateId(extra);
                string scope = string.Join(",", Options.Scope);
                Uri endPoint = Options.AuthorizationEndpoint;

                if (!string.IsNullOrWhiteSpace(Options.ApiHost))
                {
                    string host = Options.ApiHost;
                    Uri uri;
                    if (Options.ApiHost.IndexOf(":") > 0 && Uri.TryCreate(host, UriKind.RelativeOrAbsolute, out uri))
                    {
                        endPoint = new Uri(uri, endPoint.PathAndQuery);
                    }
                    else
                    {
                        endPoint = new UriBuilder(endPoint)
                        {
                            Host = host
                        }.Uri;
                    }
                }

                string authorizationEndpoint = endPoint +
                    $"?appid={Uri.EscapeDataString(Options.AppId)}" +
                    $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                    $"&response_type=code" +
                    $"&scope={Uri.EscapeDataString(scope)}" +
                    $"&state={Uri.EscapeDataString(state)}" +
                    $"#oauth_redirect";

                // Redirect Authorization Endpoint
                var redirectContext = new OAuthApplyRedirectContext(Context, Options, extra, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.RedirectPath.HasValue && Options.RedirectPath == Request.Path)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new OAuthReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };
            ticket.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    context.RedirectUri = context.RedirectUri; //WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                }
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        private string GenerateRedirectUri()
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.RedirectPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(state));
            return redirectUri;
        }

        private JObject ObtainAccessTokenAsync(string oauthToken)
        {
            return JObject.Parse(oauthToken);
        }

        private JObject ObtainUserInfoAsync(string userInfo)
        {
            return JObject.Parse(userInfo);
        }
    }
}