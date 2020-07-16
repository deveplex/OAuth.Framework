using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.Serialization;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace Microsoft.AspNet.Identity.QQ
{
    public class QQUserInfo
    {
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

        [DataMember(Name = "nickname")]
        public string Nickame { get; set; }

        [DataMember(Name = "figureurl")]
        public string FigureUrl { get; set; }

        [DataMember(Name = "figureurl_1")]
        public string FigureUrl_1 { get; set; }

        [DataMember(Name = "figureurl_2")]
        public string FigureUrl_2 { get; set; }

        [DataMember(Name = "figureurl_qq_1")]
        public string FigureUrl_QQ_1 { get; set; }

        [DataMember(Name = "figureurl_qq_2")]
        public string FigureUrl_QQ_2 { get; set; }

        [DataMember(Name = "gender")]
        public string Gender { get; set; }

        [DataMember(Name = "is_yellow_vip")]
        public string Is_Yellow_Vip { get; set; }

        [DataMember(Name = "vip")]
        public string IsVip { get; set; }

        [DataMember(Name = "yellow_vip_level")]
        public string Yellow_Vip_Level { get; set; }

        [DataMember(Name = "level")]
        public string Level { get; set; }

        [DataMember(Name = "is_yellow_year_vip")]
        public string Is_Yellow_Year_Vip { get; set; }
    }
}