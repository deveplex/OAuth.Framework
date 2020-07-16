using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.Framework
{
    //
    // 摘要:
    //     Stores information which can be used to implement account lockout, including
    //     access failures and lockout status
    //
    // 类型参数:
    //   TUser:
    //
    //   TKey:
    public interface IUserLockoutStore<TApp, in TKey> : IOAuthStore<TApp, TKey>, IDisposable where TApp : class, IClient<TKey>
    {
        Task<int> GetAccessFailedCountAsync(TApp app);
        Task<bool> GetLockoutEnabledAsync(TApp app);
        Task<DateTimeOffset> GetLockoutEndDateAsync(TApp app);
        Task<int> IncrementAccessFailedCountAsync(TApp app);
        Task ResetAccessFailedCountAsync(TApp app);
        Task SetLockoutEnabledAsync(TApp app, bool enabled);
        Task SetLockoutEndDateAsync(TApp app, DateTimeOffset lockoutEnd);
    }
}
