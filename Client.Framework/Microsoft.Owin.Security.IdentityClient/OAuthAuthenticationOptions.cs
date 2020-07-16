using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.Owin.Security.IdentityClient
{
    /// <summary>
    /// Configuration options for <see cref="OAuthAuthenticationMiddleware"/>
    /// </summary>
    public class OAuthAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// oauth_base
        /// </summary>
        internal const string Scope_Base = "oauth_base";
        /// <summary>
        /// oauth_userinfo
        /// </summary>
        internal const string Scope_UserInfo = "oauth_userinfo";

        /// <summary>
        /// 
        /// </summary>
        public Uri AuthorizationEndpoint { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Uri TokenEndpoint { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Uri TokenRefreshEndpoint { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Uri UserInfoEndpoint { get; set; }

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

        public IOAuthAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Authentication Scope
        /// </summary>
        public IList<string> Scope { get; set; }

        /// <summary>
        /// Client Id
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// Secret
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// Web Host
        /// </summary>
        public string ApiHost { set; get; }

        public OAuthAuthenticationOptions() : base(Constants.AuthenticationProvider)
        {
            AuthenticationMode = AuthenticationMode.Passive;

            Caption = Constants.Caption;
            RedirectPath = new PathString("/signin-oauth");
            Scope = new List<string>() { Scope_Base };
            BackchannelExpireTimeSpan = TimeSpan.FromSeconds(60);

            AuthorizationEndpoint = new Uri("/oauth/authorize");
            TokenEndpoint = new Uri("/oauth/access_token");
            TokenRefreshEndpoint = new Uri("/oauth/refresh_token");
            UserInfoEndpoint = new Uri("/sso/userinfo");
        }
    }
}