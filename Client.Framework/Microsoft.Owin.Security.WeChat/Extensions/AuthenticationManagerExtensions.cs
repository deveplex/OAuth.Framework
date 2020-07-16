using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using Microsoft.Owin.Security.WeChat;

namespace Microsoft.Owin.Security
{
    public static class AuthenticationManagerExtensions
    {
        /// <summary>
        ///  Get an dictionary from external login info
        /// </summary>
        /// <param name="manager"></param>
        /// <returns>All keys: openid,nickname,sex,language,city,province,country,headimgurl,privilege,unionid,</returns>
        public static async Task<string> GetWeChatLoginInfoAsync(this IAuthenticationManager manager)
        {
            return await manager.GetWeChatLoginInfoAsync("ExternalCookie");
        }

        public static async Task<string> GetWeChatLoginInfoAsync(this IAuthenticationManager manager, string authenticationType)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }

            var result = await manager.AuthenticateAsync(authenticationType);

            if (result != null && result.Identity != null && result.Identity.FindFirst(Constants.ClaimType) != null)
            {
                var value = result.Identity.FindFirst(Constants.ClaimType).Value;

                if (!string.IsNullOrEmpty(value))
                {
                    //var jObject = JObject.Parse(value);

                    //Dictionary<string, string> dict = new Dictionary<string, string>();

                    //foreach (var item in jObject)
                    //{
                    //    dict[item.Key] = item.Value == null ? null : item.Value.ToString();
                    //}

                    return await Task.FromResult(value);
                }
            }
            return null;
        }
    }
}