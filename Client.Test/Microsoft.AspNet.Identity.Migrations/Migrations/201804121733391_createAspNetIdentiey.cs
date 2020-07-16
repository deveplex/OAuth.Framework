namespace Micosoft.AspNet.Identity.Migrations
{
    using System;
    using System.Collections.Generic;
    using System.Data.Entity.Infrastructure.Annotations;
    using System.Data.Entity.Migrations;
    
    public partial class createAspNetIdentiey : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.Roles",
                c => new
                    {
                        ID = c.Long(nullable: false, identity: true),
                        RGID = c.String(nullable: false, maxLength: 256),
                        RAID = c.String(maxLength: 256),
                        NAME = c.String(nullable: false, maxLength: 128),
                        DESC = c.String(maxLength: 512),
                        REMAEK = c.String(maxLength: 256),
                        ISDEF = c.Boolean(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "0")
                                },
                            }),
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
                .Index(t => t.RGID, unique: true, name: "IX_ROLES_RGID")
                .Index(t => t.NAME, unique: true, name: "IX_ROLES_NAME");
            
            CreateTable(
                "dbo.Users",
                c => new
                    {
                        ID = c.Long(nullable: false, identity: true),
                        SGID = c.String(nullable: false, maxLength: 256),
                        USERNAME = c.String(maxLength: 256),
                        EMAIL = c.String(maxLength: 256),
                        MOBILE = c.String(maxLength: 256),
                        ISVEMAIL = c.Boolean(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "0")
                                },
                            }),
                        PWDHASH = c.String(maxLength: 512),
                        SECSTAMP = c.String(maxLength: 256),
                        ISVMOBILE = c.Boolean(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "0")
                                },
                            }),
                        ISTWOFACTOR = c.Boolean(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "0")
                                },
                            }),
                        LOCKEDDATE = c.DateTime(),
                        ISLOCKED = c.Boolean(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "0")
                                },
                            }),
                        FAILEDCOUNT = c.Int(nullable: false,
                            annotations: new Dictionary<string, AnnotationValues>
                            {
                                { 
                                    "default",
                                    new AnnotationValues(oldValue: null, newValue: "0")
                                },
                            }),
                        CRDATE = c.DateTime(nullable: false,
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
                .Index(t => t.SGID, unique: true, name: "IX_USERS_SGID")
                .Index(t => t.USERNAME, unique: true, name: "IX_USERS_USERNAME")
                .Index(t => t.EMAIL, unique: true, name: "IX_USERS_EMAIL")
                .Index(t => t.MOBILE, unique: true, name: "IX_USERS_MOBILE");
            
            CreateTable(
                "dbo.UserClaims",
                c => new
                    {
                        ID = c.Long(nullable: false, identity: true),
                        FKSGID = c.String(nullable: false, maxLength: 256),
                        TYPE = c.String(nullable: false, maxLength: 256),
                        VALUE = c.String(nullable: false, maxLength: 4000),
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
                .Index(t => new { t.FKSGID, t.TYPE }, unique: true, name: "IX_USERCLAIMS_SGID_TYPE");
            
            CreateTable(
                "dbo.UserLogins",
                c => new
                    {
                        ID = c.Long(nullable: false, identity: true),
                        FKSGID = c.String(nullable: false, maxLength: 256),
                        AUTHKEY = c.String(nullable: false, maxLength: 512),
                        PROVIDER = c.String(nullable: false, maxLength: 256),
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
                .Index(t => new { t.PROVIDER, t.AUTHKEY }, unique: true, name: "IX_USERLOGINS_PROVIDER_AUTHKEY");
            
            CreateTable(
                "dbo.UserRoles",
                c => new
                    {
                        ID = c.Long(nullable: false, identity: true),
                        FKSGID = c.String(nullable: false, maxLength: 256),
                        FKRGID = c.String(nullable: false, maxLength: 256),
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
                .Index(t => new { t.FKSGID, t.FKRGID }, unique: true, name: "IX_USERROLES_SGID_RGID");
            
        }
        
        public override void Down()
        {
            DropIndex("dbo.UserRoles", "IX_USERROLES_SGID_RGID");
            DropIndex("dbo.UserLogins", "IX_USERLOGINS_PROVIDER_AUTHKEY");
            DropIndex("dbo.UserClaims", "IX_USERCLAIMS_SGID_TYPE");
            DropIndex("dbo.Users", "IX_USERS_MOBILE");
            DropIndex("dbo.Users", "IX_USERS_EMAIL");
            DropIndex("dbo.Users", "IX_USERS_USERNAME");
            DropIndex("dbo.Users", "IX_USERS_SGID");
            DropIndex("dbo.Roles", "IX_ROLES_NAME");
            DropIndex("dbo.Roles", "IX_ROLES_RGID");
            DropTable("dbo.UserRoles",
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
            DropTable("dbo.UserLogins",
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
            DropTable("dbo.UserClaims",
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
            DropTable("dbo.Users",
                removedColumnAnnotations: new Dictionary<string, IDictionary<string, object>>
                {
                    {
                        "CRDATE",
                        new Dictionary<string, object>
                        {
                            { "default", "GETUTCDATE()" },
                        }
                    },
                    {
                        "FAILEDCOUNT",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
                    {
                        "ISDEL",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
                    {
                        "ISLOCKED",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
                    {
                        "ISTWOFACTOR",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
                    {
                        "ISVEMAIL",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
                    {
                        "ISVMOBILE",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
                });
            DropTable("dbo.Roles",
                removedColumnAnnotations: new Dictionary<string, IDictionary<string, object>>
                {
                    {
                        "ISDEF",
                        new Dictionary<string, object>
                        {
                            { "default", "0" },
                        }
                    },
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
