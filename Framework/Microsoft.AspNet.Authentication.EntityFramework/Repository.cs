using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.Data.EntityFramework
{
    //public class Repository<TEntity, TKey> : IRepository<TEntity, TKey>
    //    where TEntity : class, IEntity<TKey>
    //    where TKey : IEquatable<TKey>
    //{

    //    /// <summary>
    //    /// 初始化一个<see cref="Repository{TEntity, TKey}"/>类型的新实例
    //    /// </summary>
    //    public Repository(IUnitOfWork unitOfWork)
    //    {
    //        UnitOfWork = unitOfWork;
    //        EntitySet = ((DbContext)UnitOfWork).Set<TEntity>();
    //    }

    //    /// <summary>
    //    /// 获取 当前单元操作对象
    //    /// </summary>
    //    public IUnitOfWork UnitOfWork { get; private set; }

    //    /// <summary>
    //    /// 用于新增，更新，删除
    //    /// </summary>
    //    protected DbSet<TEntity> EntitySet { get; private set; }

    //    /// <summary>
    //    /// 获取当前实体类型的查询数据集，数据将使用不跟踪变化的方式来查询
    //    /// </summary>
    //    public IQueryable<TEntity> Entities
    //    {
    //        get { return EntitySet.AsNoTracking(); }
    //    }
    //}
}
