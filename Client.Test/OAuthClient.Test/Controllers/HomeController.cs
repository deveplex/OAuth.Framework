using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace Microsoft.AspNet.Mvc.Controllers
{
    public class HomeController : HttpController
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public async Task<ActionResult> Contact()
        {
            if (Request.QueryString["code"] == null)
            {
                string authorizationEndpoint = "http://localhost:39912/oauth/authorize" +
                    $"?appid={Uri.EscapeDataString("123456")}" +
                    $"&redirect_uri={Uri.EscapeDataString(Request.Url.ToString())}" +
                    $"&response_type=code" +
                    $"&scope={Uri.EscapeDataString("scope_nnnnn")}" +
                    $"&state={Uri.EscapeDataString("lllllllllll")}" +
                    $"#wechat_redirect";

                return Redirect(authorizationEndpoint);
            }
            else
            {
                using (var _httpClient = new HttpClient())
                {
                    var code = Request.QueryString["code"];
                    var requestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("appid", "123456"),
                    new KeyValuePair<string, string>("secret", "123456"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    //new KeyValuePair<string, string>("redirect_uri", redirectUri),
                };
                    var requestContent = new FormUrlEncodedContent(requestParameters);
                    // 通过code获取access_token
                    var response = await _httpClient.PostAsync("http://localhost:39912/oauth/authorize", requestContent);
                    response.EnsureSuccessStatusCode();
                    string oauthTokenResponse = await response.Content.ReadAsStringAsync();

                    JObject oauth2Token = JObject.Parse(oauthTokenResponse);
                }
            }

            return View();
        }




        public ActionResult GetData()
        {
            //var uu = new UserInfoManager("IdentityConnection");
            //var dd = uu.GetUserInfo();

            //return Json(dd);
            return Json(new { });
        }
        public ActionResult hhhh()
        {
            //var uu = new UserInfoManager("IdentityConnection");

            //uu.Register(new dfd { UserName = "19999999999", IdentityType = Deveplex.Identity.Entitys.IdentityTypes.Mobile, Password = "123456" });

            return Json(new { });
        }
    }
}

namespace System.Web.Mvc
{
    public class JsonNetResult : JsonResult
    {
        public JsonNetResult()
        {
            JsonRequestBehavior = JsonRequestBehavior.DenyGet;
        }

        public override void ExecuteResult(ControllerContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            if (JsonRequestBehavior == JsonRequestBehavior.DenyGet &&
                String.Equals(context.HttpContext.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("GetNotAllowed");
            }

            HttpResponseBase response = context.HttpContext.Response;

            if (!String.IsNullOrEmpty(ContentType))
            {
                response.ContentType = ContentType;
            }
            else
            {
                response.ContentType = "application/json";
            }
            if (ContentEncoding != null)
            {
                response.ContentEncoding = ContentEncoding;
            }
            if (Data != null)
            {
                //JsonTextWriter writer = new JsonTextWriter(response.Output)
                //{
                //    Formatting = Formatting.None
                //};
                ////JsonSerializerSettings SerializerSettings = JsonConvert.DefaultSettings.;
                //JsonSerializer serializer = JsonSerializer.Create(/*SerializerSettings*/);
                //serializer.Serialize(writer, Data);
                //writer.Flush();


#pragma warning disable 0618

                response.Write(JsonConvert.SerializeObject(Data));
#pragma warning restore 0618
            }
        }
    }
    public class HttpController : Controller
    {
        protected override JsonResult Json(object data, string contentType, Encoding contentEncoding)
        {
            return new JsonNetResult()
            {
                Data = data,
                ContentType = contentType,
                ContentEncoding = contentEncoding
            };
        }
        protected override JsonResult Json(object data, string contentType, Encoding contentEncoding, JsonRequestBehavior behavior)
        {
            return new JsonNetResult()
            {
                Data = data,
                ContentType = contentType,
                ContentEncoding = contentEncoding,
                JsonRequestBehavior = behavior
            };
        }
    }
}
