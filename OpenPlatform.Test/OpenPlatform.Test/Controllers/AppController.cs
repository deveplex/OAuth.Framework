using Deveplex.Identity.Security;
using Deveplex.OAuth;
using Microsoft.AspNet.Identity.Application;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.OpenPlatform.Application;
using Microsoft.Identity;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Transactions;
using System.Web;
using System.Web.Mvc;

namespace OpenPlatform.Test.Controllers
{
    public partial class AppController : BaseController
    {
        public AppController()
        {

        }

        [HttpGet]
        public ActionResult Index()
        {
            string userId = CryptoService.SHA128("78892591965534528805");

            //var appList = await ClientManager.GetClientsAsync(userId);
            ////JsonSerializerSettings settings = new JsonSerializerSettings();
            ////settings.MissingMemberHandling = MissingMemberHandling.Ignore;
            ////settings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
            //string fff = Newtonsoft.Json.JsonConvert.SerializeObject(appList);
            //ViewBag.TestData = fff;

            return View();
        }

        [HttpGet]
        public ActionResult Details(string appId)
        {
            ViewBag.AppId = appId;
            return View();
        }

        [HttpGet]
        public ActionResult Add()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Add(AddViewModel model)
        {
            using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.RepeatableRead }, TransactionScopeAsyncFlowOption.Enabled))
            {
                try
                {
                    string userId = CryptoService.SHA128("78892591965534528805");
                    var app = new Client
                    {
                        OwnerId = userId,
                        UserName = Guid.NewGuid().ToString("n"),
                        Name = model.AppName,
                        Description = model.Description
                    };
                    var result = await ClientManager.CreateAsync(app);
                    if (!result.Succeeded)
                    {
                        //result = await ClientManager.AddPasswordAsync(app.AppId, Guid.NewGuid().ToString("n"));
                        //if (result.Succeeded)
                        //{
                        return RedirectToLocal("/App/Index");
                        //}
                    }
                    scope.Complete();
                }
                catch
                {
                }
                finally
                {
                }
            }
            return View();
        }
        public class AddViewModel { public string AppName { get; set; } public string Description { get; set; } }

        public async Task<ActionResult> GetAppList()
        {
            string userId = CryptoService.SHA128("78892591965534528805");
            var appList = await ClientManager.GetClientsAsync(userId);

            return Json(appList, JsonRequestBehavior.AllowGet);
        }

        public async Task<ActionResult> GetAppDetails(string appId)
        {
            //JObject appDetails = null;
            var app = await ClientManager.FindByNameAsync(appId);
            if (app == null)
            {
            }
            //var secret = await ClientManager.GetSecretAsync(appId);
            //var redirectUri =  await ClientManager.GetRedirectUriAsync(appId);
            //var details= JToken.FromObject(new { Secret= secret, RedirectUri= redirectUri });

            // appDetails = JObject.FromObject(app);
            // appDetails.Merge(details);
            //var fff= appDetails.ToObject<object>();

            return Json(new
            {
                AppId = app.UserName,
                Secret = app.PasswordHash,
                app.Name,
                app.Description,
                RedirectUri = app.CallbackUrl,
                app.Status,
            });
        }

        public async Task<ActionResult> ResetSecret(string appId)
        {
            using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.RepeatableRead }, TransactionScopeAsyncFlowOption.Enabled))
            {
                object aaa = new { };
                try
                {
                    IdentityResult result = IdentityResult.Failed();
                    var app = await ClientManager.FindByNameAsync(appId);
                    if (app == null)
                    {
                        return Json(aaa);
                    }
                    if (await ClientManager.HasPasswordAsync(app.Id))
                    {
                        result = await ClientManager.ChangePasswordAsync(app.Id, app.PasswordHash, Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));

                    }
                    else
                    {
                        result = await ClientManager.AddPasswordAsync(app.Id, Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
                    }
                    if (result.Succeeded)
                    {
                        aaa = new
                        {
                            AppId = app.UserName,
                            Secret = app.PasswordHash,
                            app.Name,
                            app.Description,
                            RedirectUri = app.CallbackUrl,
                            app.Status,
                        };
                    }
                    scope.Complete();
                }
                catch (Exception ex)
                {
                }
                finally
                {
                }
                return Json(aaa);
            }
        }

        public async Task<ActionResult> ModifyRedirectUri(string appId, string url)
        {
            using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.RepeatableRead }, TransactionScopeAsyncFlowOption.Enabled))
            {
                try
                {
                    string redirecturl = null;
                    var app = await ClientManager.FindByNameAsync(appId);
                    if (app == null)
                    {
                    }
                    //var result = await ClientManager.SetRedirectUriAsync(appId, url);
                    //if (result.Succeeded)
                    //{
                    //    redirecturl = await ClientManager.GetRedirectUriAsync(appId);
                    //}
                    //scope.Complete();
                    return Json(redirecturl);
                }
                catch
                {
                }
                finally
                {
                }
            }
            return Json(null);
        }
    }

    public partial class AppController : BaseController
    {
        private ApplicationClientManager _clientManager;

        private ILogger _logger;

        // 用于在添加外部登录名时提供 XSRF 保护
        private const string XsrfKey = "XsrfId";

        public AppController(ApplicationClientManager clientManager, ILogger logger)
        {
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
                if (_clientManager != null)
                {
                    _clientManager.Dispose();
                    _clientManager = null;
                }
            }
        }
    }
}