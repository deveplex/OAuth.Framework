using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace ResourceServer.Test.Controllers
{
    [Authorize]
    public class OAuthController : ApiController
    {
        IHttpActionResult UserInfo()
        {
            return Json(new
            {
                name = this.User.Identity.Name
            });
        }
    }
}
