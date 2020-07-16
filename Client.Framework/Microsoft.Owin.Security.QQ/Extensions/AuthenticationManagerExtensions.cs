using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Owin.Security.QQ;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security
{
    public static class AuthenticationManagerExtensions
    {
        public static async Task<string> GetQQLoginInfoAsync(this IAuthenticationManager manager)
        {
            return await GetQQLoginInfoAsync(manager, "ExternalCookie");
        }

        public static async Task<string> GetQQLoginInfoAsync(this IAuthenticationManager manager, string authenticationType)
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