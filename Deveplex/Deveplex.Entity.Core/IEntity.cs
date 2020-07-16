using System;
using System.Collections.Generic;

namespace Deveplex.Entity
{
    public interface IEntity : IEntity<string>
    {
    }

    public interface IEntity<TKey>
    {
        TKey Id { get; set; }
        bool IsDeleted { get; set; }
    }
}