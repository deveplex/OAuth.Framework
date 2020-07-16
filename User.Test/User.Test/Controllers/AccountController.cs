using Deveplex.Identity;
using Deveplex.Identity.Common;
using Microsoft.AspNet.Identity.Application;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Mvc;
using Microsoft.Identity;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;
using System.Web;
using System.Web.Mvc;

namespace AspNet.Mvc.Controllers
{
    public partial class AccountController : BaseController
    {
        public AccountController()
        {
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult Register(string returnUrl)
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return RedirectToLocal("~/");
            }

            using (ApplicationDbContext db = new ApplicationDbContext())
            //using (IdentityDbContext db = new IdentityDbContext("DefaultConnection"))
            //using (Microsoft.Managed.Extensibility.EntityFramework.ManagedDbContext db = new Microsoft.Managed.Extensibility.EntityFramework.ManagedDbContext("DefaultConnection"))
            //using (System.Data.Entity.DbContext db = new System.Data.Entity.DbContext("DefaultConnection"))
            {
                //IQueryable<IdentityUser> ggg = db.Set<IdentityUser>().AsNoTracking();
                //var query = from r in ggg
                //            select r;
                //System.Collections.Generic.List<IdentityUser> jkjk = query.ToList();
                //System.Collections.Generic.List<IdentityRole> jkjk = db.Database.SqlQuery<IdentityRole>("SELECT * FROM [Roles]", new object[] { }).ToListAsync().Result;
            }

            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var result = await RegisterUserAsync(model);
                if (result.Succeeded)
                {
                    return RedirectToLocal(returnUrl);
                }
                AddError(result);
            }
            AddError("", "注册失败");
            ViewBag.returnUrl = returnUrl;
            return View(model);
        }

        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            return new AuthenticationChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            HttpContext.Session.Clear();

            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return View("ExternalLoginFailure");
            }

            var signInResult = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (signInResult)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    if (1 == 1)
                    {
                        return RedirectToLocal(returnUrl);
                    }
                    else if (2==2)
                    {                    
                        // 如果用户没有帐户，则提示该用户创建帐户

                        ViewBag.ReturnUrl = returnUrl;
                        ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                        return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { UserName = loginInfo.DefaultUserName });
                    }
                    else
                    {
                        var result = await SignInExternalUserLoginAsync(new ExternalLoginConfirmationViewModel { UserName = loginInfo.DefaultUserName }, loginInfo, isPersistent: false);
                        if (result.Succeeded)
                        {
                            return RedirectToLocal(returnUrl);
                        }
                        return View("ExternalLoginFailure");
                    }
            }
        }

        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                // 从外部登录提供程序获取有关用户的信息
                var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (loginInfo == null)
                {
                    return View("ExternalLoginFailure");
                }

                var result = await SignInExternalUserLoginAsync(model, loginInfo, isPersistent: model.IsPersistent);
                if (result.Succeeded)
                {
                    return RedirectToLocal(returnUrl);
                }
                AddError(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return RedirectToLocal(returnUrl);
            //return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Logoff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
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
                catch(Exception ex)
                {
                    result = IdentityResult.Failed(ex.Message);
                }
                finally
                {
                }
                return result;
            }
        }

        public async Task<IdentityResult> RegisterUserAsync(RegisterViewModel model)
        {
            using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.RepeatableRead }, TransactionScopeAsyncFlowOption.Enabled))
            {
                var result = IdentityResult.Failed();
                try
                {
                    var user = new IdentityUser
                    {
                        UserCode = IdentityGenerator.RandomUserNumeral20(),
                        UserName = model.UserName
                    };
                    if (model.IdentityType != IdentityTypes.UserName)
                    {
                        user.UserName = IdentityGenerator.RandomUserName();
                    }
                    result = await UserManager.CreateAsync(user, model.Password);
                    if (!result.Succeeded)
                    {
                        return result;
                    }
                    switch (model.IdentityType)
                    {
                        case IdentityTypes.PhoneNumber:
                            break;
                        case IdentityTypes.Email:
                            break;
                        default:
                            break;
                    }
                    ////var role = await RoleManager.FindByIdAsync("0");
                    //result = await UserManager.AddAccountAttributeAsync(user.Id, new Microsoft.AspNet.Identity.Framework.ExternalAttributeInfo { AccountType = 0 });
                    //if (!result.Succeeded)
                    //{
                    //    return result;
                    //}
                    scope.Complete();
                }
                catch (Exception ex)
                {
                    result = IdentityResult.Failed(ex.Message);
                }
                finally
                {
                }
                return result;
            }
        }

        public async Task<IdentityResult> SignInExternalUserLoginAsync(ExternalLoginConfirmationViewModel model, ExternalLoginInfo loginInfo, bool isPersistent)
        {
            using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.RepeatableRead }, TransactionScopeAsyncFlowOption.Enabled))
            {
                var result = IdentityResult.Failed();
                try
                {
                    //var user = new ApplicationUser { UserName = model.UserName };
                    //result = await UserManager.CreateAsync(user);
                    //if (result.Succeeded)
                    //{
                    //    result = await UserManager.AddLoginAsync(user.Id, loginInfo.Login);
                    //    if (result.Succeeded)
                    //    {
                    //        var role = await RoleManager.FindByIdAsync("0");
                    //        result = await UserManager.AddUserRoleAsync(user.Id, role.Id);
                    //        if (result.Succeeded)
                    //        {
                    //            await SignInManager.SignInAsync(user, isPersistent: isPersistent, rememberBrowser: false);
                    //        }
                    //    }
                    //}
                    //scope.Complete();
                }
                catch (Exception ex)
                {
                    result = IdentityResult.Failed(ex.Message);
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
                return _roleManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
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