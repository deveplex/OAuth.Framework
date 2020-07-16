using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security;

namespace Microsoft.Owin.Security.OAuth
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class OAuthAuthenticatedTokenContext : BaseContext
    {
        /// <summary>
        /// 授权接口调用凭证
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// 刷新接口调用凭证
        /// </summary>
        public string RefreshToken { get; }

        /// <summary>
        /// 网页授权接口调用凭证超时时间，单位（秒）
        /// </summary>
        public TimeSpan? ExpiresIn { get; }

        public OAuthAuthenticatedTokenContext(IOwinContext context, string accessToken) : base(context)
        {
            AccessToken = accessToken;
        }
    }
}