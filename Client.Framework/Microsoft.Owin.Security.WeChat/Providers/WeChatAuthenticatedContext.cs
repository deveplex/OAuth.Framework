using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security;

namespace Microsoft.Owin.Security.WeChat
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class WeChatAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        private readonly JObject _AuthenInfo;

        /// <summary>
        /// 普通用户的标识，对当前开发者帐号唯一
        /// </summary>
        public string OpenId
        {
            get
            {
                return GetSafeValue("openid", _AuthenInfo);
            }
        }

        /// <summary>
        /// 用户统一标识。针对同一个开放平台帐号下的应用，同一用户的unionid是唯一的。
        /// </summary>
        public string UnionId
        {
            get
            {
                return GetSafeValue("unionid", _AuthenInfo);
            }
        }

        /// <summary>
        /// 网页授权接口调用凭证
        /// </summary>
        public string AccessToken
        {
            get
            {
                return GetSafeValue("access_token", _AuthenInfo);
            }
        }

        /// <summary>
        /// 刷新接口调用凭证
        /// </summary>
        public string RefreshToken
        {
            get
            {
                return GetSafeValue("refresh_token", _AuthenInfo);
            }
        }

        /// <summary>
        /// 网页授权接口调用凭证超时时间，单位（秒）
        /// </summary>
        public TimeSpan? ExpiresIn
        {
            get
            {
                var expires = GetSafeValue("expires_in", _AuthenInfo);
                int num;
                if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out num))
                {
                    return new TimeSpan?(TimeSpan.FromSeconds((double)num));
                }

                return null;
            }
        }

        /// <summary>
        /// 用户授权的作用域，使用逗号（,）分隔
        /// </summary>
        public string Scope
        {
            get
            {
                return GetSafeValue("scope", _AuthenInfo);
            }
        }

        /// <summary>
        /// 用户唯一标识
        /// 当UnionId不为空时，AuthenticationKey为<see cref="UnionId"/>，否则为 <see cref="OpenId"/>
        /// </summary>
        public string AuthenticationKey
        {
            get
            {
                if (string.IsNullOrWhiteSpace(this.UnionId))
                {
                    return OpenId;
                }
                else
                {
                    return UnionId;
                }

            }
        }

        public WeChatAuthenticatedContext(IOwinContext context, JObject authenInfo) : base(context)
        {
            if (authenInfo == null)
            {
                throw new ArgumentNullException("AuthenInfo");
            }

            _AuthenInfo = authenInfo;
        }

        private string GetSafeValue(string name, IDictionary<string, JToken> dictionary)
        {
            if (!dictionary.ContainsKey(name))
            {
                return null;
            }
            return dictionary[name].ToString();
        }
    }
}