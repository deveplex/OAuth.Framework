using Microsoft.Owin.Security.OAuth;
using System;

namespace Microsoft.Owin.Security.IdentityServer
{
    public class IdentityAuthorizationServerOptions : OAuthAuthorizationServerOptions
    {
        /// <summary>
        /// 
        /// </summary>
        public string Caption
        {
            get
            {
                return base.Description.Caption;
            }
            set
            {
                base.Description.Caption = value;
            }
        }


        public IdentityAuthorizationServerOptions() : base()
        {
#if DEBUG
            //HTTPS is allowed only AllowInsecureHttp = false
            AllowInsecureHttp = true;
#endif
            AuthenticationMode = AuthenticationMode.Active;

             Caption = Constants.Caption;
            AuthorizationCodeExpireTimeSpan = TimeSpan.FromMinutes(5); //authorization_code 过期时间
            AccessTokenExpireTimeSpan = TimeSpan.FromHours(2); //access_token 过期时间

            AuthorizeEndpointPath = new PathString("/oauth/authorize"); //获取 authorization_code 授权服务请求地址
            TokenEndpointPath = new PathString("/oauth/token"); //获取 access_token 授权服务请求地址

            Provider = new IdentityAuthorizationServerProvider(/*ServerId*/);
            AuthorizationCodeProvider = new IdentityAuthorizationCodeProvider(); //authorization_code 授权服务
            RefreshTokenProvider = new IdentityRefreshTokenProvider(); //refresh_token 授权服务
        }
    }
}