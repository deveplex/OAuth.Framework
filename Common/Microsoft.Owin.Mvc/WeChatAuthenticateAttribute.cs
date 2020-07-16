using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Mvc.Filters;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.OAuth.Mvc
{
    public class WeChatAuthenticateAttribute : FilterAttribute, IAuthenticationFilter
    {
        public string AppId { get; set; }
        public string AppSecret { get; set; }
        public List<string> Scope { get; set; }

        private string AuthenticationType = "WeChat";
        private string OpenPlatformAuthorizationEndpoint { get; }
        private string MediaPlatformAuthorizationEndpoint { get; }
        private string TokenEndpoint { get; }
        private string RefreshTokenEndpoint { get; }
        private string UserInfoEndpoint { get; }

        private const string Scope_Base = "snsapi_base";
        private const string Scope_UserInfo = "snsapi_userinfo";
        private const string Scope_UserLogin = "snsapi_login";

        public WeChatAuthenticateAttribute()
        {
            Scope = new List<string>() { Scope_Base };

            OpenPlatformAuthorizationEndpoint = @"https://open.weixin.qq.com/connect/qrconnect";
            MediaPlatformAuthorizationEndpoint = @"https://open.weixin.qq.com/connect/oauth2/authorize";
            TokenEndpoint = @"https://api.weixin.qq.com/sns/oauth2/access_token";
            RefreshTokenEndpoint = @"https://api.weixin.qq.com/sns/oauth2/refresh_token";
            UserInfoEndpoint = @"https://api.weixin.qq.com/sns/userinfo";
        }

        public void OnAuthentication(AuthenticationContext context/*, CancellationToken cancellationToken*/)
        {
            var user = context.HttpContext.User;
            if (user == null || !user.Identity.IsAuthenticated)
            {
                //从请求中获取Authorization Code，并利用它来获取Access Token
                string authorizationCode;
                if (context.HttpContext.Request.TryGetAuthorizationCode(out authorizationCode))
                {
                    string returnUrl = context.HttpContext.Request.QueryString["returnUrl"];
                    if (string.IsNullOrWhiteSpace(returnUrl))
                    {
                        context.Result = new RedirectResult(returnUrl);
                    }

                    //但前请求URI去除“?code={authorizationcode}”部分作为rediect_uri参数
                    string query = string.Format("code={0}", authorizationCode);
                    string redirectUri = context.HttpContext.Request.Url.AbsoluteUri.Replace(query, "").TrimEnd('?');

                    using (HttpClient httpClient = new HttpClient())
                    {
                        var requestParameters = new List<KeyValuePair<string, string>>()
                        {
                            new KeyValuePair<string, string>("appid", AppId),
                            new KeyValuePair<string, string>("secret", AppSecret),
                            new KeyValuePair<string, string>("code", authorizationCode),
                            new KeyValuePair<string, string>("grant_type", "authorization_code"),
                            new KeyValuePair<string, string>("redirect_uri", redirectUri),
                        };
                        var requestContent = new FormUrlEncodedContent(requestParameters);
                        var response = httpClient.PostAsync(TokenEndpoint, requestContent/*, cancellationToken*/).Result;
                        response.EnsureSuccessStatusCode();

                        //得到Access Token并Attach到请求的Properties字典中
                        string oauthTokenResponse = response.Content.ReadAsStringAsync().Result;
                        JObject oauth2Token = JObject.Parse(oauthTokenResponse);
                        var accessToken = oauth2Token.Value<string>("access_token");
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return;// Task.FromResult<object>(null);
                        }

                        var scope = oauth2Token.Value<string>("scope");
                        var openId = oauth2Token.Value<string>("openid");
                        JObject userInfo = JObject.FromObject(new { openid = openId });

                        var unionId = oauth2Token.Value<string>("unionid");
                        if (!string.IsNullOrWhiteSpace(unionId))
                        {
                            userInfo.Add(new { unionid = unionId });
                        }

                        if (Scope.Contains(Scope_UserInfo) || Scope.Contains(Scope_UserLogin))
                        {
                            // 获取用户个人信息
                            requestParameters = new List<KeyValuePair<string, string>>()
                            {
                            new KeyValuePair<string, string>("access_token", accessToken),
                            new KeyValuePair<string, string>("openid", openId),
                            };
                            requestContent = new FormUrlEncodedContent(requestParameters);
                            response = httpClient.PostAsync(UserInfoEndpoint, requestContent/*, cancellationToken*/).Result;
                            response.EnsureSuccessStatusCode();

                            if (response.IsSuccessStatusCode)
                            {
                                string userInfoResponse = response.Content.ReadAsStringAsync().Result;

                                userInfo = JObject.Parse(userInfoResponse);
                            }
                        }

                        var AuthenticationKey = openId ?? unionId;
                        var identity = new ClaimsIdentity(AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                        if (!string.IsNullOrEmpty(AuthenticationKey))
                        {
                            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, AuthenticationKey, ClaimValueTypes.String, AuthenticationType));
                        }
                        if (oauth2Token.HasValues)
                        {
                            identity.AddClaim(new Claim("urn:wechat:authenticationtoken", oauth2Token.ToString(), ClaimValueTypes.String, AuthenticationType));
                        }

                        if (userInfo.HasValues)
                        {
                            identity.AddClaim(new Claim("urn:wechat:authenticationidentity", userInfo.ToString(), ClaimValueTypes.String, AuthenticationType));
                        }

                        var username = userInfo.Value<string>("nickname");
                        if (!string.IsNullOrWhiteSpace(username))
                        {
                            identity.AddClaim(new Claim(ClaimTypes.Name, username, ClaimValueTypes.String, AuthenticationType));
                        }

                        var email = userInfo.Value<string>("email");
                        if (!string.IsNullOrWhiteSpace(email))
                        {
                            identity.AddClaim(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String, AuthenticationType));
                        }

                        context.HttpContext.GetOwinContext().Authentication.SignIn(new AuthenticationProperties(), identity);
                        //user = new GenericPrincipal(identity, new string[] { });
                    }
                }
            }
        }

        public void OnAuthenticationChallenge(AuthenticationChallengeContext context/*, CancellationToken cancellationToken*/)
        {
            var user = context.HttpContext.User;
            if (user == null || !user.Identity.IsAuthenticated)
            {
                string redirectUri = context.HttpContext.Request.Url.ToString();
                var state = Guid.NewGuid().ToString("n");
                string scope = string.Join(",", Scope);
                Uri endPoint = new Uri(MediaPlatformAuthorizationEndpoint);
                if (Scope.Contains(Scope_UserInfo))
                {
                    endPoint = new Uri(MediaPlatformAuthorizationEndpoint);
                }
                else if (Scope.Contains(Scope_UserLogin))
                {
                    endPoint = new Uri(OpenPlatformAuthorizationEndpoint);
                }

                string authorizationEndpoint = endPoint +
                $"?appid={Uri.EscapeDataString(AppId)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&response_type=code" +
                $"&scope={Uri.EscapeDataString(scope)}" +
                $"&state={Uri.EscapeDataString(state)}" +
                $"#wechat_redirect";

                context.Result = new RedirectResult(authorizationEndpoint/*, context.Request*/);
            }
        }

        //public Task<HttpResponseMessage> ExecuteActionFilterAsync(ActionContext context, CancellationToken cancellationToken, Func<Task<HttpResponseMessage>> continuation)
        //{
        //    HttpResponseMessage response = continuation().Result;


        //    //if (context.SignInAsAuthenticationType != null && context.RequestContext.Principal != null)
        //    //{
        //    //    ClaimsIdentity signInIdentity = context.RequestContext.Principal.Identity;
        //    //    if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
        //    //    {
        //    //        signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
        //    //    }
        //    //    context.Authentication.SignIn(context.Properties, signInIdentity);
        //    //}

        //    //string accessToken;
        //    //if (actionContext.Request.TryGetAccessToken(out accessToken))
        //    //{
        //    //    response.SetAccessToken(actionContext.Request, accessToken);
        //    //}
        //    return Task.FromResult<HttpResponseMessage>(response);
        //}
    }
}
