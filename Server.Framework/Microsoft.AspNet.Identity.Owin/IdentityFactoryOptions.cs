using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity.Owin
{
    public class IdentityFactoryOptions<T>
        where T : IDisposable
    {
        public IdentityFactoryOptions()
        {
        }

        /// <summary>
        /// Member of Microsoft.AspNet.Identity.Owin.IdentityFactoryOptions<T>
        /// </summary>
        //public IOwinContext Context { set; get; }

        /// <summary>
        /// Member of Microsoft.AspNet.Identity.Owin.IdentityFactoryOptions<T>
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { set; get; }

        /// <summary>
        /// Member of Microsoft.AspNet.Identity.Owin.IdentityFactoryOptions<T>
        /// </summary>
        public IIdentityFactoryProvider<T> Provider { set; get; }

    }
}
