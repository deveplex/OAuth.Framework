using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.Owin.Security.QQ
{
    /// <summary>
    /// Configuration options for <see cref="QQAuthenticationMiddleware"/>
    /// </summary>
    public class QQAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// 用来获取用户的基本信息的
        /// </summary>
        internal const string Scope_UserInfo = "get_user_info";

        /// <summary>
        /// QQ开放平台授权地址
        /// </summary>
        internal string AuthorizationEndpoint { get; }

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
        internal string UserOpenIdEndpoint { get; }

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

        public TimeSpan BackchannelTimeout { get; set; }

        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public PathString RedirectPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IQQAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// 用户授权的作用域
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        /// 应用唯一标识
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// 应用密钥
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// QQ服务器主机
        /// </summary>
        public string ApiHost { set; get; }

        public QQAuthenticationOptions() : base(Constants.AuthenticationProvider)
        {
            AuthenticationMode = AuthenticationMode.Passive;

            Caption = Constants.Caption;
            RedirectPath = new PathString("/signin-qq");
            Scope = new List<string>() { Scope_UserInfo };
            BackchannelTimeout = TimeSpan.FromSeconds(60);

            AuthorizationEndpoint = @"https://graph.qq.com/oauth2.0/authorize";
            TokenEndpoint = @"https://graph.qq.com/oauth2.0/token";
            RefreshTokenEndpoint = @"https://graph.qq.com/oauth2.0/token";
            UserOpenIdEndpoint = @"https://graph.qq.com/oauth2.0/me";
            UserInfoEndpoint = @"https://graph.qq.com/user/get_user_info";
        }
    }
}