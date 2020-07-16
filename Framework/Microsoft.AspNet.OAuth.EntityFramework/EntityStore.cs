using System;
using System.Data.Entity;
using System.Data.Repositorys;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.EntityFramework
{
    /// <summary>
    ///     EntityFramework based IIdentityEntityStore that allows query/manipulation of a TEntity set
    /// </summary>
    /// <typeparam name="TEntity">Concrete entity type, i.e .User</typeparam>
    internal class EntityStore<TEntity> : IRepository<TEntity>
        where TEntity : class
    {
        /// <summary>
        ///     Constructor that takes a Context
        /// </summary>
        /// <param name="context"></param>
        public EntityStore(DbContext context)
        {
            Context = context ?? throw new ArgumentNullException("context");
            EntitySet = context.Set<TEntity>();
        }

        public bool IsLoaded { get; set; }

        /// <summary>
        ///     Context for the store
        /// </summary>
        protected DbContext Context { get; private set; }

        protected DbSet<TEntity> EntitySet { get; private set; }

        public IQueryable<TEntity> Entities
        {
            get { return EntitySet.AsNoTracking(); }
        }

        /// <summary>
        ///     FindAsync an entity by ID
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns></returns>
        public async Task<TEntity> FindAsync(Expression<Func<TEntity, bool>> predicate)
        {
            //return EntitySet.FindAsync(id);

            var entity = await EntitySet.FirstOrDefaultAsync(predicate);
            return entity;
        }

        /// <summary>
        ///     Insert an entity
        /// </summary>
        /// <param name="entity"></param>
        public TEntity Add(TEntity entity)
        {
            IsLoaded = false;
            return EntitySet.Add(entity);
        }

        /// <summary>
        ///     Mark an entity for deletion
        /// </summary>
        /// <param name="entity"></param>
        public TEntity Remove(TEntity entity)
        {
            IsLoaded = false;
            return EntitySet.Remove(entity);
        }

        /// <summary>
        ///     Update an entity
        /// </summary>
        /// <param name="entity"></param>
        public virtual TEntity Update(TEntity entity)
        {
            try
            {
                if (entity != null)
                {
                    IsLoaded = false;
                    RemoveHoldingEntityInContext(entity);

                    var updated = Context.Set<TEntity>().Attach(entity);
                    Context.Entry(entity).State = EntityState.Modified;
                }
            }
            catch (System.Data.Entity.Validation.DbEntityValidationException dbex)
            {

            }
            return entity;
        }

        private bool RemoveHoldingEntityInContext(TEntity entity)
        {
            var objContext = ((System.Data.Entity.Infrastructure.IObjectContextAdapter)Context).ObjectContext;
            var objSet = objContext.CreateObjectSet<TEntity>();
            var entityKey = objContext.CreateEntityKey(objSet.EntitySet.Name, entity);

            Object foundEntity;
            var exists = objContext.TryGetObjectByKey(entityKey, out foundEntity);

            if (exists)
            {
                objContext.Detach(foundEntity);
            }

            return (exists);
        }
    }
}
