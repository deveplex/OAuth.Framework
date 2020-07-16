using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.OAuth.Core
{
    public interface IToken : IToken<string>
    {
    }

    public interface IToken<out TKey>
        where TKey : IEquatable<TKey>
    {
        TKey Id { get; }
    }
}
