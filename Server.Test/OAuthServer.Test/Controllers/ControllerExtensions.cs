using Microsoft.AspNet.Identity;
using Microsoft.Identity;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace Microsoft.AspNet.Mvc
{
    public class BaseController : Controller
    {
        public ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        public void AddError(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        public void AddError(string key, Exception exception)
        {
            ModelState.AddModelError(key, exception);
        }

        public void AddError(string key, string errorMessage)
        {
            ModelState.AddModelError(key, errorMessage);
        }
        protected new System.Web.Mvc.JsonResult Json(object data)
        {
            return Json(data, data.GetType(), Formatting.None, new JsonSerializerSettings(), null /* contentType */, null /* contentEncoding */, JsonRequestBehavior.DenyGet);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, Formatting formatting)
        {
            return Json(data, data.GetType(), formatting, new JsonSerializerSettings(), null /* contentType */, null /* contentEncoding */, JsonRequestBehavior.DenyGet);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, Formatting formatting, JsonRequestBehavior behavior)
        {
            return Json(data, data.GetType(), formatting, new JsonSerializerSettings(), null /* contentType */, null /* contentEncoding */, behavior);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, JsonSerializerSettings settings)
        {
            return Json(data, data.GetType(), Formatting.None, settings, null /* contentType */, null /* contentEncoding */, JsonRequestBehavior.DenyGet);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, JsonSerializerSettings settings, JsonRequestBehavior behavior)
        {
            return Json(data, data.GetType(), Formatting.None, settings, null /* contentType */, null /* contentEncoding */, behavior);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, Type type, JsonSerializerSettings settings)
        {
            return Json(data, type, Formatting.None, settings, null /* contentType */, null /* contentEncoding */, JsonRequestBehavior.DenyGet);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, Type type, JsonSerializerSettings settings, JsonRequestBehavior behavior)
        {
            return Json(data, type, Formatting.None, settings, null /* contentType */, null /* contentEncoding */, behavior);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, Formatting formatting, JsonSerializerSettings settings)
        {
            return Json(data, data.GetType(), formatting, settings, null /* contentType */, null /* contentEncoding */, JsonRequestBehavior.DenyGet);
        }
        protected virtual System.Web.Mvc.JsonResult Json(object data, Type type, Formatting formatting, JsonSerializerSettings settings)
        {
            return Json(data, type, formatting, settings, null /* contentType */, null /* contentEncoding */, JsonRequestBehavior.DenyGet);
        }

        protected new System.Web.Mvc.JsonResult Json(object data, string contentType)
        {
            return Json(data, data.GetType(), Formatting.None, new JsonSerializerSettings(), contentType, null /* contentEncoding */, JsonRequestBehavior.DenyGet);
        }

        protected virtual new System.Web.Mvc.JsonResult Json(object data, string contentType, Encoding contentEncoding)
        {
            return Json(data, data.GetType(), Formatting.None, new JsonSerializerSettings(), contentType, contentEncoding, JsonRequestBehavior.DenyGet);
        }

        protected new System.Web.Mvc.JsonResult Json(object data, JsonRequestBehavior behavior)
        {
            return Json(data, data.GetType(), Formatting.None, new JsonSerializerSettings(), null /* contentType */, null /* contentEncoding */, behavior);
        }

        protected new System.Web.Mvc.JsonResult Json(object data, string contentType, JsonRequestBehavior behavior)
        {
            return Json(data, data.GetType(), Formatting.None, new JsonSerializerSettings(), contentType, null /* contentEncoding */, behavior);
        }

        protected override System.Web.Mvc.JsonResult Json(object data, string contentType, Encoding contentEncoding, JsonRequestBehavior behavior)
        {
            return Json(data, data.GetType(), Formatting.None, new JsonSerializerSettings(), contentType, contentEncoding, behavior);
        }

        protected virtual System.Web.Mvc.JsonResult Json(object data, Type type, Formatting formatting, JsonSerializerSettings settings, string contentType, Encoding contentEncoding, JsonRequestBehavior behavior)
        {
            //protected virtual System.Web.Mvc.JsonResult Json(object value, Formatting formatting, params JsonConverter[] converters);
            //protected virtual System.Web.Mvc.JsonResult Json(object value, params JsonConverter[] converters);

            return new JsonResult
            {
                Data = data,
                Type = type,
                Formatting = formatting,
                Settings = settings,
                ContentType = contentType,
                ContentEncoding = contentEncoding,
                JsonRequestBehavior = behavior
            };
        }
    }

    public class JsonResult : System.Web.Mvc.JsonResult
    {
        public JsonResult()
            : base()
        {
            JsonRequestBehavior = JsonRequestBehavior.DenyGet;
        }

        public Type Type;

        public Formatting Formatting;

        public JsonSerializerSettings Settings;

        public override void ExecuteResult(ControllerContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            if (JsonRequestBehavior == JsonRequestBehavior.DenyGet &&
                String.Equals(context.HttpContext.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("MvcResources.JsonRequest_GetNotAllowed");
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
                response.Write(Newtonsoft.Json.JsonConvert.SerializeObject(Data, Type, Formatting, Settings));
            }
        }
    }

    /// <summary>
    /// Base64编码转换安全的URL
    /// </summary>
    public static class URLSecureBase64
    {
        /// <summary>
        /// Base64String字符串编码
        /// </summary>
        /// <param name="base64String">原Base64String字符串</param>
        /// <returns>编码的文本字符串.</returns>
        public static string EncodeUrlSecureBase64(this Uri that, string base64String)
        {
            var uriSecureBase64 = base64String.Replace('+', '-').Replace('/', '_').TrimEnd('=');
            return uriSecureBase64;
        }

        /// <summary>
        /// 解码安全的URL文本字符串的Base64
        /// </summary>
        /// <param name="urlSecureBase64">已经过UrlSecureBase64编码的字符串.</param>
        /// <returns>Cadena de texto decodificada.</returns>
        public static string DecodeUrlSecureBase64(this Uri that, string urlSecureBase64)
        {
            urlSecureBase64 = urlSecureBase64.Replace('-', '+').Replace('_', '/');
            switch (urlSecureBase64.Length % 4)
            {
                case 2:
                    urlSecureBase64 += "==";
                    break;
                case 3:
                    urlSecureBase64 += "=";
                    break;
            }
            var bytes = Convert.FromBase64String(urlSecureBase64);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
    }
}