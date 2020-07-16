using Microsoft.AspNet.Identity.Application;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Identity;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;
using System.Web;
using System.Web.Mvc;

namespace Microsoft.AspNet.Mvc.Controllers
{
    public partial class AccountController : BaseController
    {
        public AccountController()
        {
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return RedirectToLocal(returnUrl);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return RedirectToLocal(returnUrl);
            }

            if (ModelState.IsValid)
            {
                var result = await SignInUserLoginAsync(model);
                if (result.Succeeded)
                {
                    return RedirectToLocal(returnUrl);
                }
            }
            AddError("", "无效的用户名或密码");
            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Logoff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToLocal("");
        }

        public async Task<IdentityResult> SignInUserLoginAsync(LoginViewModel model)
        {
            using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.RepeatableRead }, TransactionScopeAsyncFlowOption.Enabled))
            {
                var result = IdentityResult.Failed();
                try
                {
                    var password = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(model.Password));
                    var user = await UserManager.FindAsync(model.UserName, password);
                    if (user != null)
                    {
                        result = IdentityResult.Success;
                        //var user = new
                        //{
                        //    UserId = Guid.NewGuid().ToString("n"),
                        //    UserName = model.UserName
                        //};

                        //var identity = new ClaimsIdentity(DefaultAuthenticationTypes.ApplicationCookie, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                        //identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.UserId, ClaimValueTypes.String, DefaultAuthenticationTypes.ApplicationCookie));
                        //identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName, ClaimValueTypes.String, DefaultAuthenticationTypes.ApplicationCookie));
                        //AuthenticationManager.SignIn(new AuthenticationProperties { IsPersistent = model.IsPersistent }, identity);
                        //return RedirectToLocal(returnUrl);

                        //var claimsIdentity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
                        AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                        await SignInManager.SignInAsync(user, isPersistent: model.IsPersistent, rememberBrowser: false);
                    }
                    scope.Complete();
                }
                catch
                {
                    result = IdentityResult.Failed();
                }
                finally
                {
                }
                return result;
            }
        }
    }

    public partial class AccountController : BaseController
    {
        private ApplicationUserManager _userManager;
        private ApplicationSignInManager _signInManager;
        private ApplicationRoleManager _roleManager;
        private ILogger _logger;

        // 用于在添加外部登录名时提供 XSRF 保护
        private const string XsrfKey = "XsrfId";

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager, ApplicationRoleManager roleManager, ILogger logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        public IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ApplicationRoleManager RoleManager
        {
            get
            {
                return _roleManager ?? HttpContext.GetOwinContext().Get<ApplicationRoleManager>();
            }
            private set
            {
                _roleManager = value;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                base.Dispose(disposing);
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }

                if (_roleManager != null)
                {
                    _roleManager.Dispose();
                    _roleManager = null;
                }
            }

        }
    }
}