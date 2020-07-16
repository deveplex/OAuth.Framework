using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class LoginViewModel
{
    [Required]
    [Display(Name = "用户名")]
    public string UserName { get; set; }

    [Required]
    [Display(Name = "密码")]
    public string Password { get; set; }

    public bool IsPersistent { get; set; }
}

public class RegisterViewModel
{
    [Required]
    [Display(Name = "用户名")]
    public string UserName { get; set; }

    [Required]
    [Display(Name = "密码")]
    public string Password { get; set; }

    [Required]
    [Display(Name = "验证码")]
    public string Code { get; set; }

    [Required]
    public IdentityTypes IdentityType { get; set; }
}

public class ExternalLoginConfirmationViewModel
{
    [Required]
    [Display(Name = "用户名")]
    public string UserName { get; set; }

    public bool IsPersistent { get; set; }
}

public class ExternalLoginListViewModel
{
    public string ReturnUrl { get; set; }
}

public enum IdentityTypes
{
    //[DisplayName("")]
    [Description("用户名")]
    UserName,
    [Description("电子邮箱")]
    Email,
    [Description("手机号")]
    PhoneNumber,
    [Description("身份证")]
    PID,
    [Description("QQ")]
    QQ,
    [Description("微信")]
    Weixin,
    [Description("淘宝")]
    Taobao,
    [Description("支付宝")]
    AliPay,
    [Description("微博")]
    Weibo,
}
