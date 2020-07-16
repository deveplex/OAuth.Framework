// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Owin;
using System;

namespace Microsoft.AspNet.Identity.Owin
{
    public interface IIdentityFactoryProvider<T>
        where T : IDisposable
    {
        T Create(IdentityFactoryOptions<T> options, IOwinContext context);
        void Dispose(IdentityFactoryOptions<T> options, T instance);
    }
}
