using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security;
using Microsoft.Owin.Infrastructure;

namespace Microsoft.Owin.Security.WeChat
{
    /// <summary>
    ///
    /// </summary>
    internal class WeChatAuthenticationHandler : AuthenticationHandler<WeChatAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public WeChatAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        /// <summary>
        /// 生成状态码
        /// 因微信公众号授权对state字段的限制，这里改为使用Cookie存储数据
        /// 详细请参考：https://mp.weixin.qq.com/wiki?id=mp1465199793_BqlKA&t=0.2918104504400387
        /// </summary>
        /// <param name="extra"></param>
        /// <returns></returns>
        private string GenerateStateId(AuthenticationProperties properties)
        {
            string stateId = Guid.NewGuid().ToString("n");
            properties.Dictionary["stateId"] = stateId;
            string key = $"_{Options.AuthenticationType}State_{stateId}";
            string stateValue = Options.StateDataFormat.Protect(properties);
            base.Response.Cookies.Append(key, stateValue, new CookieOptions
            {
                HttpOnly = true,
                Secure = base.Request.IsSecure
            });
            return stateId;
        }

        /// <summary>
        /// 验证状态码有效性
        /// </summary>
        /// <param name="stateId"></param>
        /// <param name="extra"></param>
        /// <returns></returns>
        private bool ValidateStateId(string stateId, ILogger logger, out AuthenticationProperties properties)
        {
            string key = $"_{Options.AuthenticationType}State_{stateId}";
            string protectedText = Request.Cookies[key];
            bool flag = string.IsNullOrWhiteSpace(protectedText);
            bool result;
            if (flag)
            {
                logger.WriteError("Invalid return state, unable to redirect.");
                properties = null;
                result = false;
            }
            else
            {
                properties = Options.StateDataFormat.Unprotect(protectedText);
                bool flag2 = properties == null || !properties.Dictionary.ContainsKey("stateId") || properties.Dictionary["stateId"] != stateId;
                if (flag2)
                {
                    logger.WriteError("Invalid return state, unable to redirect.");
                    properties = null;
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

                if (!ValidateStateId(state, _logger, out properties))
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                if (code == null)
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + Uri.SchemeDelimiter + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.RedirectPath;

                var requestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("appid", Options.AppId),
                    new KeyValuePair<string, string>("secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                };
                var requestContent = new FormUrlEncodedContent(requestParameters);
                // 通过code获取access_token
                var response = await _httpClient.PostAsync(Options.TokenEndpoint, requestContent, Request.CallCancelled);
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

                if (Options.Scope.Contains(WeChatAuthenticationOptions.Scope_UserInfo) || Options.Scope.Contains(WeChatAuthenticationOptions.Scope_UserLogin))
                {
                    // 获取用户个人信息
                    requestParameters = new List<KeyValuePair<string, string>>()
                    {
                        new KeyValuePair<string, string>("access_token", accessToken),
                        new KeyValuePair<string, string>("openid", openId),
                    };
                    requestContent = new FormUrlEncodedContent(requestParameters);
                    response = await _httpClient.PostAsync(Options.UserInfoEndpoint, requestContent, Request.CallCancelled);
                    //response = await _httpClient.GetAsync(Options.UserInfoEndpoint + $"?access_token={Uri.EscapeDataString(accessToken)}&openid={Uri.EscapeDataString(openId)}", Request.CallCancelled);
                    response.EnsureSuccessStatusCode();
                    string userInfoResponse = await response.Content.ReadAsStringAsync();

                    userInfo = ObtainUserInfoAsync(userInfoResponse);
                }

                var context = new WeChatAuthenticatedContext(Context, oauth2Token);
                await Options.Provider.Authenticated(context);

                var identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                if (!string.IsNullOrEmpty(context.AuthenticationKey))
                {
                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.AuthenticationKey, ClaimValueTypes.String, Options.AuthenticationType));
                }

                if (userInfo.HasValues)
                {
                    identity.AddClaim(new Claim(Constants.ClaimType, userInfo.ToString(), ClaimValueTypes.String, Options.AuthenticationType));
                }

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
        ///  执行401跳转
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

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                string state = GenerateStateId(properties);
                string scope = string.Join(",", Options.Scope);
                Uri endPoint = new Uri(Options.MediaPlatformAuthorizationEndpoint);
                if (Options.Scope.Contains(WeChatAuthenticationOptions.Scope_UserInfo))
                {
                    endPoint = new Uri(Options.MediaPlatformAuthorizationEndpoint);
                }
                else if (Options.Scope.Contains(WeChatAuthenticationOptions.Scope_UserLogin))
                {
                    endPoint = new Uri(Options.OpenPlatformAuthorizationEndpoint);
                }

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
                    $"#wechat_redirect";

                // 跳转到 授权服务器 页面
                var redirectContext = new WeChatApplyRedirectContext(Context, Options, properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.RedirectPath.HasValue && Options.RedirectPath == Request.Path)
            {
                return await InvokeReplyPathAsync();
            }
            return false;
        }

        public async Task<bool> InvokeReplyPathAsync()
        {
            AuthenticationTicket ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new WeChatReturnEndpointContext(Context, ticket)
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
                string redirectUri = context.RedirectUri;
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    redirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                }
                Response.Redirect(redirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
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