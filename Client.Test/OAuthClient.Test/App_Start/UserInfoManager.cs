using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Deveplex.Identity.EntityFramework
{
    //public class dfd { public string UserName; public IdentityTypes IdentityType; public string Password; }
    //public class UserInfoManager
    //{
    //    public AuthenticationDbContext Context { get; }

    //    public UserInfoManager(string nameOrConnectionString)
    //    {
    //        Context = new AuthenticationDbContext(nameOrConnectionString);
    //    }

    //    public string Login(string userName, string password)
    //    {
    //        return JObject.FromObject(new { }).ToString();
    //    }
    //    public string Register<T>(T model) where T : dfd, new()
    //    {
    //        if (model == null)
    //        {
    //            throw new ArgumentNullException("model");
    //        }

    //        using (var scope = new TransactionScope(TransactionScopeOption.Required))
    //        {
    //            try
    //            {
    //                //
    //                var user = new Account
    //                {
    //                    UserId = IdentityGenerator.RandomUserNumeral20(),
    //                    UserName = (model.IdentityType == IdentityTypes.UserName) ? model.UserName : IdentityGenerator.RandomUserName(),
    //                };
    //                user.CheckCode = CryptoService.HashCheckCode(user.CheckString());
    //                Account newUser = Context.Account.Add(user);
    //                Context.SaveChanges();
    //                //
    //                if (model.IdentityType != IdentityTypes.UserName)
    //                {
    //                    var exuser = new SecurityAccount
    //                    {
    //                        AccountID = newUser.AccountId,
    //                        ValidationID = model.UserName,
    //                        IdentityType = model.IdentityType,
    //                    };
    //                    exuser.CheckCode = CryptoService.HashCheckCode(exuser.CheckString());
    //                    var exUser = Context.SecurityAccount.Add(exuser);
    //                    Context.SaveChanges();
    //                }
    //                //
    //                var arrt = new AccountAttribute
    //                {
    //                    AccountId = newUser.AccountId,
    //                };
    //                //arrt.CheckCode = CryptoService.SHA256(arrt.CheckString()).Replace("-", "");
    //                Context.AccountAttribute.Add(arrt);
    //                Context.SaveChanges();
    //                //
    //                var pwd = new PasswordCryptography
    //                {
    //                    AccountID = newUser.AccountId,
    //                    UserKey = IdentityGenerator.RandomBase64String(12),
    //                };
    //                pwd.Password = CryptoService.PasswordCrypto(model.Password + pwd.UserKey);
    //                pwd.CheckCode = CryptoService.HashCheckCode(pwd.CheckString());
    //                Context.Password.Add(pwd);
    //                Context.SaveChanges();

    //                scope.Complete();
    //            }
    //            finally
    //            {
    //            }
    //        }

    //        return JObject.FromObject(new { }).ToString();
    //    }

    //    public dynamic GetUserInfo()
    //    {
    //        var f = from a in Context.Account
    //                select a;
    //        var dd = f.ToList();

    //        return dd;//JObject.FromObject(new { }).ToString();

    //    }
    //}
}

