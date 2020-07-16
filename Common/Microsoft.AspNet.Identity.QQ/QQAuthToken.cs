using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.Serialization;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace Microsoft.AspNet.Identity.QQ
{
    /// <summary>
    /// 
    /// </summary>
    [DataContract]
    public class WeChatAuthToken
    {
        /// <summary>
        /// 网页授权接口调用凭证
        /// </summary>
        [DataMember(Name = "access_token")]
        public string AccessToken { get; set; }

        /// <summary>
        /// 刷新接口调用凭证
        /// </summary>
        [DataMember(Name = "refresh_token")]
        public string RefreshToken { get; set; }

        /// <summary>
        /// 网页授权接口调用凭证超时时间，单位（秒）
        /// </summary>
        [DataMember(Name = "expires_in")]
        public int ExpiresIn { get; set; }

        /// <summary>
        /// 用户授权的作用域，使用逗号（,）分隔
        /// </summary>
        [DataMember(Name = "scope")]
        public string Scope { get; set; }

        /// <summary>
        /// 普通用户的标识，对当前开发者帐号唯一
        /// </summary>
        [DataMember(Name = "openid")]
        public string OpenId { get; set; }

        /// <summary>
        /// 用户统一标识。针对同一个开放平台帐号下的应用，同一用户的unionid是唯一的。
        /// </summary>
        [DataMember(Name = "unionid")]
        public string UnionId { get; set; }
    }
}