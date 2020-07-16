using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth
{
    public interface IScope: IScope<string>
    {
    }

    public interface IScope<TKey>
    {
        TKey Id { get; set; }

        string Name { get; set; }
    }
}
