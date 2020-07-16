using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.Serialization;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace Microsoft.AspNet.Identity.WeChat
{
    /// <summary>
    /// 
    /// </summary>
    [DataContract]
    public class WeChatUserInfo
    {
        /// <summary>
        /// 普通用户的标识，对当前开发者帐号唯一
        /// </summary>
        [DataMember(Name = "openid")]
        public string OpenId { get; set; }

        /// <summary>
        /// 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
        /// </summary>
        [DataMember(Name = "unionid")]
        public string UnionId { get; set; }

        [DataMember(Name = "nickname")]
        public string Nickame { get; set; }

        [DataMember(Name = "sex")]
        public string Sex { get; set; }

        [DataMember(Name = "province")]
        public string Province { get; set; }

        [DataMember(Name = "city")]
        public string City { get; set; }

        [DataMember(Name = "country")]
        public string Country { get; set; }

        [DataMember(Name = "headimgurl")]
        public string HeadimgUrl { get; set; }

        [DataMember(Name = "privilege")]
        public string Privilege { get; set; }
    }
}