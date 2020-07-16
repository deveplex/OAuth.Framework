using Deveplex.Entity;
using System;

namespace Deveplex.OAuth
{
    public class AppToken : IEntity<string>
    {
        public virtual string Id { get; set; }
        public virtual string AppId { get; set; }
        public virtual string Subject { get; set; }
        public virtual string Ticket { get; set; }
        public virtual DateTime IssuedUtc { get; set; }
        public virtual DateTime ExpiresUtc { get; set; }
        public bool IsDeleted { get; set; }
    }
}