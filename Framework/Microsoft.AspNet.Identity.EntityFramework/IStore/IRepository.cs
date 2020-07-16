using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace System.Data.Repositorys
{
    internal interface IRepository<TEntity>
        where TEntity : class
    {
        IQueryable<TEntity> Entities { get; }

        Task<TEntity> FindAsync(Expression<Func<TEntity, bool>> predicate);

        TEntity Add(TEntity entity);

        TEntity Update(TEntity entity);

        TEntity Remove(TEntity entity);
    }
}
