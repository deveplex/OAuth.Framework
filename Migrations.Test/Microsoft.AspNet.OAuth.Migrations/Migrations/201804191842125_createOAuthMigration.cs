namespace Microsoft.AspNet.OAuth.Migrations
{
    using System;
    using System.Collections.Generic;
    using System.Data.Entity.Infrastructure.Annotations;
    using System.Data.Entity.Migrations;
    
    public partial class createOAuthMigration : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.Clients",
                c => new
                    {
                        ID = c.Long(nullable: false, identity: true),
                        FKSGID = c.String(nullable: false, maxLength: 256),
                        NAME = c.String(nullable: false, maxLength: 128),
                        APPID = c.String(nullable: false, maxLength: 256),
                        SECRET = c.String(nullable: false, maxLength: 512),
                        CBURL = c.String(maxLength: 2046),
                        DESC = c.String(maxLength: 2000),
                        STATUS = c.Int(nullable: false),
                        UPDATE = c.DateTime(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "GETUTCDATE()")
                                },
                            }),
                        HASHKEY = c.String(maxLength: 256),
                        ISDEL = c.Boolean(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "0")
                                },
                            }),
                    })
                .PrimaryKey(t => t.ID)
                .Index(t => t.FKSGID, unique: true, name: "IX_CLIENTS_SGID")
                .Index(t => t.NAME, unique: true, name: "IX_CLIENTS_NAME")
                .Index(t => t.APPID, unique: true, name: "IX_CLIENTS_APPID");
            
        }
        
        public override void Down()
        {
            DropIndex("dbo.Clients", "IX_CLIENTS_APPID");
            DropIndex("dbo.Clients", "IX_CLIENTS_NAME");
            DropIndex("dbo.Clients", "IX_CLIENTS_SGID");
            DropTable("dbo.Clients",
                removedColumnAnnotations: new Dictionary<string, IDictionary<string, object>>
                {
                    {
                        "ISDEL",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
                    {
                        "UPDATE",
                        new Dictionary<string, object>
                        {
                            { "default", "GETUTCDATE()" },
                        }
                    },
                });
        }
    }
}
