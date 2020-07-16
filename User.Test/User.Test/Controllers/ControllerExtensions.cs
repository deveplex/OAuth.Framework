using Microsoft.AspNet.Identity;
using Microsoft.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AspNet.Mvc.Controllers
{
    public class BaseController: Controller
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
            int i = 0;
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(i.ToString(), error);
                i++;
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

    }
}