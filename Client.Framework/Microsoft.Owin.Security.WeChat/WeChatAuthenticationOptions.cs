using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.Owin.Security.WeChat
{
    /// <summary>
    /// Configuration options for <see cref="WeChatAuthenticationMiddleware"/>
    /// </summary>
    public class WeChatAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// 用于静默方式发起的授权
        /// </summary>
        internal const string Scope_Base = "snsapi_base";
        /// <summary>
        /// 用于在公众号发起的授权，获取用户的基本信息
        /// </summary>
        internal const string Scope_UserInfo = "snsapi_userinfo";
        /// <summary>
        /// 用于在开放平台发起的授权，获取用户的基本信息
        /// </summary>
        internal const string Scope_UserLogin = "snsapi_login";

        /// <summary>
        /// 微信开放平台授权地址
        /// </summary>
        internal string OpenPlatformAuthorizationEndpoint { get; }

        /// <summary>
        /// 微信公众号授权地址
        /// </summary>
        internal string MediaPlatformAuthorizationEndpoint { get; }

        /// <summary>
        /// 
        /// </summary>
        internal string TokenEndpoint { get; }

        /// <summary>
        /// 
        /// </summary>
        internal string RefreshTokenEndpoint { get; }

        /// <summary>
        /// 
        /// </summary>
        internal string UserInfoEndpoint { get; }


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

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public TimeSpan BackchannelExpireTimeSpan { get; set; }

        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public PathString RedirectPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IWeChatAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// 用户授权的作用域
        /// </summary>
        public IList<string> Scope { get; set; }

        /// <summary>
        /// 应用唯一标识，在微信开放平台提交应用审核通过后获得
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// 应用密钥，在微信开放平台提交应用审核通过后获得
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// 微信服务器主机
        /// 详细请参考：https://mp.weixin.qq.com/wiki?id=mp1465199793_BqlKA&t=0.2918104504400387
        /// </summary>
        public string ApiHost { set; get; }

        public WeChatAuthenticationOptions() : base(Constants.AuthenticationProvider)
        {
            AuthenticationMode = AuthenticationMode.Passive;

            Caption = Constants.Caption;
            RedirectPath = new PathString("/signin-weixin");
            Scope = new List<string>() { Scope_Base };
            BackchannelExpireTimeSpan = TimeSpan.FromSeconds(60);

            OpenPlatformAuthorizationEndpoint = @"https://open.weixin.qq.com/connect/qrconnect";
            MediaPlatformAuthorizationEndpoint = @"https://open.weixin.qq.com/connect/oauth2/authorize";
            TokenEndpoint = @"https://api.weixin.qq.com/sns/oauth2/access_token";
            RefreshTokenEndpoint = @"https://api.weixin.qq.com/sns/oauth2/refresh_token";
            UserInfoEndpoint = @"https://api.weixin.qq.com/sns/userinfo";
        }
    }
}