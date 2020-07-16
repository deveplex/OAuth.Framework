using System;

namespace Microsoft.AspNet.Identity.Application
{

    // 可以通过向 ApplicationUser 类添加更多属性来为用户添加配置文件数据。若要了解详细信息，请访问 http://go.microsoft.com/fwlink/?LinkID=317594。
    public class ApplicationUser
    {
        public int Display { get; set; }
        public string NickName { get; set; }
        public string Name { get; set; }

        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public TimeSpan? ExpiresIn { get; set; }

        //public override string UserName
        //{
        //    get
        //    {
        //        string displayName = null;
        //        switch ((DisplayTypes)Display)
        //        {
        //            case DisplayTypes.Nick:
        //                displayName = string.IsNullOrEmpty(NickName) ? null : NickName;
        //                break;
        //            case DisplayTypes.Name:
        //                displayName = string.IsNullOrEmpty(Name) ? null : Name;
        //                break;
        //            case DisplayTypes.PhoneNumber:
        //                displayName = string.IsNullOrEmpty(PhoneNumber) ? null : PhoneNumber;
        //                break;
        //            case DisplayTypes.Email:
        //                displayName = string.IsNullOrEmpty(Email) ? null : Email;
        //                break;
        //            default:
        //                displayName = base.UserName;
        //                break;
        //        }
        //        return displayName ?? NickName ?? Name ?? PhoneNumber ?? Email;
        //    }
        //    set
        //    {
        //        base.UserName = string.IsNullOrEmpty(value) ? null : value;
        //    }
        //}
    }

    public class ApplicationRole
    {
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public enum DisplayTypes : int
    {
        None = 0,
        Nick = 1,
        Name = 2,
        PhoneNumber = 3,
        Email = 4
    }

}
