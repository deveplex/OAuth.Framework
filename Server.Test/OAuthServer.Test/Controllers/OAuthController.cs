using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.OAuth.Application;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace OAuthServer.Test.Controllers
{
    public partial class OAuthController : BaseController
    {
        public OAuthController()
        {

        }

        [HttpGet]
        public ActionResult Authorize(AuthorizeViewModel model)
        {
            if (Response.StatusCode != 200)
            {
                return View("AuthorizeError");
            }
            if (!ModelState.IsValid)
            {
                return View("AuthorizeError");
            }

            if (!User.Identity.IsAuthenticated)
            {
                AuthenticationManager.Challenge();
                return new HttpUnauthorizedResult();
            }

            var scopes = model.Scope.Split(',');
            ViewBag.IdentityName = AuthenticationManager.User.Identity.Name;
            ViewBag.scopes = scopes;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Authorize(AuthorizeViewModel model, bool isGrant)
        {
            if (Response.StatusCode != 200)
            {
                return View("AuthorizeError");
            }

            if (ModelState.IsValid)
            {
                var scopes = model.Scope.Split(',');

                if (isGrant)
                {
                    var ticket = AuthenticationManager.AuthenticateAsync(User.Identity.AuthenticationType).Result;
                    var identity = ticket != null ? ticket.Identity : null;
                    if (identity == null)
                    {
                        return View("AuthorizeError");
                    }
                    var oauthIdentity = identity;
                    if (!identity.AuthenticationType.Equals(OAuthDefaults.AuthenticationType, StringComparison.Ordinal))
                    {
                        oauthIdentity = new ClaimsIdentity(identity.Claims, OAuthDefaults.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
                    }
                    foreach (var scope in scopes)
                    {
                        oauthIdentity.AddClaim(new Claim("urn:oauth:scope", scope, oauthIdentity.AuthenticationType));
                    }
                    AuthenticationManager.SignIn(identity);
                }
                else
                {
                    AuthenticationManager.SignOut();
                    AuthenticationManager.Challenge();
                    return new HttpUnauthorizedResult();
                }
            }
            return View();
        }

        public ActionResult AuthorizeError()
        {
            return View();
        }
    }

    public partial class OAuthController : BaseController
    {
        //private ApplicationUserManager _userManager;
        //private ApplicationSignInManager _signInManager;
        //private ApplicationRoleManager _roleManager;
        private ApplicationClientManager _clientManager;

        private ILogger _logger;

        // 用于在添加外部登录名时提供 XSRF 保护
        private const string XsrfKey = "XsrfId";

        public OAuthController(/*ApplicationUserManager userManager, ApplicationSignInManager signInManager, ApplicationRoleManager roleManager,*/ ApplicationClientManager clientManager, ILogger logger)
        {
            //_userManager = userManager;
            //_signInManager = signInManager;
            //_roleManager = roleManager;
            _clientManager = clientManager;
            _logger = logger;
        }

        public IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        public ApplicationClientManager ClientManager
        {
            get
            {
                return _clientManager ?? HttpContext.GetOwinContext().Get<ApplicationClientManager>();
            }
            private set
            {
                _clientManager = value;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                base.Dispose(disposing);
                //if (_userManager != null)
                //{
                //    _userManager.Dispose();
                //    _userManager = null;
                //}

                //if (_signInManager != null)
                //{
                //    _signInManager.Dispose();
                //    _signInManager = null;
                //}

                //if (_roleManager != null)
                //{
                //    _roleManager.Dispose();
                //    _roleManager = null;
                //}
                if (_clientManager != null)
                {
                    _clientManager.Dispose();
                    _clientManager = null;
                }
            }

            base.Dispose(disposing);
        }
    }
}
