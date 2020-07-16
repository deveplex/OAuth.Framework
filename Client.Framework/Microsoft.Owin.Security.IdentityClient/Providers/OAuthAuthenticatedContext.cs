using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security;

namespace Microsoft.Owin.Security.IdentityClient
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class OAuthAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        private readonly JObject _AuthenInfo;

        /// <summary>
        /// Open Id
        /// </summary>
        public string OpenId
        {
            get
            {
                return GetSafeValue("openid", _AuthenInfo);
            }
        }

        /// <summary>
        /// Unionid Id。
        /// </summary>
        public string UnionId
        {
            get
            {
                return GetSafeValue("unionid", _AuthenInfo);
            }
        }

        /// <summary>
        /// Access Token
        /// </summary>
        public string AccessToken
        {
            get
            {
                return GetSafeValue("access_token", _AuthenInfo);
            }
        }

        /// <summary>
        /// Refresh Token
        /// </summary>
        public string RefreshToken
        {
            get
            {
                return GetSafeValue("refresh_token", _AuthenInfo);
            }
        }

        /// <summary>
        /// ExpiresIn
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
        /// Scope
        /// </summary>
        public string Scope
        {
            get
            {
                return GetSafeValue("scope", _AuthenInfo);
            }
        }

        /// <summary>
        /// when UnionId not null,AuthenticationKey is <see cref="UnionId"/>,then <see cref="OpenId"/>
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

        public OAuthAuthenticatedContext(IOwinContext context, JObject authenInfo) : base(context)
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