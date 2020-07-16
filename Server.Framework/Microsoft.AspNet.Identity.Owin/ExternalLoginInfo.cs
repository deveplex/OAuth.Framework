// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Identity;
using System.Security.Claims;

namespace Microsoft.AspNet.Identity.Owin
{
    public class ExternalLoginInfo
    {
        public ExternalLoginInfo() { }

        public UserLoginInfo Login { get; set; }
        public string DefaultUserName { get; set; }
        public string Email { get; set; }
        public ClaimsIdentity ExternalIdentity { get; set; }
    }
}
