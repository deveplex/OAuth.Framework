using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Microsoft.AspNet.Mvc
{
    using System.Net;
    using System.Net.Http;
    using System.Web.Helpers;
    using System.Web.Http.Controllers;
    using System.Web.Http;

    public class UnauthenticateAttribute : AuthorizeAttribute
    {
        private string _ErrorMessage = "服务端拒绝访问：没有访问权限";
        public string ErrorMessage
        {
            get { return _ErrorMessage; }
            set { _ErrorMessage = value; }
        }

        protected override void HandleUnauthorizedRequest(HttpActionContext filterContext)
        {
            base.HandleUnauthorizedRequest(filterContext);

            var response = filterContext.Response = filterContext.Response ?? new HttpResponseMessage();
            response.StatusCode = HttpStatusCode.Forbidden;
            var content = new
            {
                success = false,
                errs = new[] { _ErrorMessage }
            };
            response.Content = new StringContent(Json.Encode(content), Encoding.UTF8, "application/json");
        }
    }
}
