using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Mvc
{
    using System.Web.Mvc;
    using System.Web.Mvc.Filters;

    public class OAuthAuthenticateAttribute : AuthorizeAttribute
    {
        public string LoginProvider { get; set; }
        public string RedirectUri { get; set; }

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            filterContext.Result = new AuthenticationChallengeResult(LoginProvider, RedirectUri);
        }
    }

    public class AuthorizationAttribute : FilterAttribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationContext filterContext)
        {
        }
    }

    public class AuthenticateAttribute : IAuthenticationFilter
    {
        public void OnAuthentication(AuthenticationContext filterContext)
        {
        }

        public void OnAuthenticationChallenge(AuthenticationChallengeContext filterContext)
        {
            var user = filterContext.HttpContext.User;
            if (user == null || !user.Identity.IsAuthenticated)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
        }
    }
}

namespace Microsoft.AspNet.WebApi
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Web;
    using System.Web.Http.Controllers;
    using System.Web.Http.Filters;
    using System.Web.Http.Results;

    public class AuthorizationAttribute : FilterAttribute, IAuthorizationFilter
    {
        public Task<HttpResponseMessage> ExecuteAuthorizationFilterAsync(HttpActionContext actionContext, CancellationToken cancellationToken, Func<Task<HttpResponseMessage>> continuation)
        {
            throw new NotImplementedException();
        }
    }
    public class AuthenticateAttribute : FilterAttribute, IAuthenticationFilter
    {
        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }

    /*
    public class AuthenticateAttribute : FilterAttribute, IAuthenticationFilter, IActionFilter
    {
    public const string CookieName = "AccessToken";
    public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
    {
    //从请求中获取Access Token
    string accessToken;
    if (context.Request.TryGetAccessToken(out accessToken))
    {
    return Task.FromResult<object>(null);
    }

    //从请求中获取Authorization Code，并利用它来获取Access Token
    string authorizationCode;
    if (context.Request.TryGetAuthorizationCode(out authorizationCode))
    {
    string query = string.Format("code={0}", authorizationCode);

    //但前请求URI去除“?code={authorizationcode}”部分作为rediect_uri参数
    string callbackUri = context.Request.RequestUri.AbsoluteUri.Replace(query, "").TrimEnd('?');
    using (HttpClient client = new HttpClient())
    {
    Dictionary<string, string> postData = new Dictionary<string, string>();
    postData.Add("client_id", "000000004810C359");
    postData.Add("redirect_uri", callbackUri);
    postData.Add("client_secret", "37cN-CGV9JPzolcOicYwRGc9VHdgvg6y");
    postData.Add("code", authorizationCode);
    postData.Add("grant_type", "authorization_code");
    HttpContent httpContent = new FormUrlEncodedContent(postData);
    HttpResponseMessage tokenResponse = client.PostAsync("https://login.live.com/oauth20_token.srf", httpContent).Result;

    //得到Access Token并Attach到请求的Properties字典中
    if (tokenResponse.IsSuccessStatusCode)
    {
    string content = tokenResponse.Content.ReadAsStringAsync().Result;
    JObject jObject = JObject.Parse(content);
    accessToken = (string)JObject.Parse(content)["access_token"];
    context.Request.AttachAccessToken(accessToken);

    return Task.FromResult<object>(null);
    }
    else
    {
    return Task.FromResult<HttpResponseMessage>(tokenResponse);
    }
    }
    }
    return Task.FromResult<object>(null);
    }

    public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
    {
    string accessToken;
    if (!context.Request.TryGetAccessToken(out accessToken))
    {
    string clientId = "000000004810C359";
    string redirectUri = context.Request.RequestUri.ToString();
    string scope = "wl.signin%20wl.basic";
    string url = "https://login.live.com/oauth20_authorize.srf";
    url += "?response_type=code";
    url += "&redirect_uri={0}&client_id={1}&scope={2}";
    url = String.Format(url, redirectUri, clientId, scope);
    context.Result = new RedirectResult(new Uri(url), context.Request);
    }
    return Task.FromResult<object>(null);
    }

    public Task<HttpResponseMessage> ExecuteActionFilterAsync(HttpActionContext actionContext, CancellationToken cancellationToken, Func<Task<HttpResponseMessage>> continuation)
    {
    HttpResponseMessage response = continuation().Result;
    string accessToken;
    if (actionContext.Request.TryGetAccessToken(out accessToken))
    {
    response.SetAccessToken(actionContext.Request, accessToken);
    }
    return Task.FromResult<HttpResponseMessage>(response);
    }
    }
    */

}

namespace System.Net.Http
{
    using System.Net.Http.Headers;
    using System.Web;

    public static class Extensions
    {
        public static bool TryGetAuthorizationCode(this HttpRequestBase request, out string authorizationCode)
        {
            authorizationCode = request.QueryString["code"];
            return !string.IsNullOrEmpty(authorizationCode);
        }

        public static bool TryGetAuthorizationCode(this HttpRequestMessage request, out string authorizationCode)
        {
            authorizationCode = HttpUtility.ParseQueryString(request.RequestUri.Query)["code"];
            return !string.IsNullOrEmpty(authorizationCode);
        }

        public static void AttachAccessToken(this HttpRequestMessage request, string accessToken)
        {
            string token;
            if (!request.TryGetAccessToken(out token))
            {
                request.Properties["CookieName"] = accessToken;
            }
        }

        public static bool TryGetAccessToken(this HttpRequestMessage request, out string accessToken)
        {
            //从请求的Cookie中获取Access Token
            accessToken = null;
            CookieHeaderValue cookieValue = request.Headers.GetCookies("CookieName").FirstOrDefault();
            if (null != cookieValue)
            {
                accessToken = cookieValue.Cookies.FirstOrDefault().Value;
                return true;
            }

            //获取Attach的Access Token
            object token;
            if (request.Properties.TryGetValue("CookieName", out token))
            {
                accessToken = (string)token;
                return true;
            }
            return false;
        }
    }
}
