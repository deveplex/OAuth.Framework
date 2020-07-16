// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.OAuth;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Validates users before they are saved
    /// </summary>
    /// <typeparam name="TApp"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    internal class ClientValidator<TApp, TKey> : IIdentityValidator<TApp>
        where TApp : class, IClient<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="manager"></param>
        public ClientValidator(OAuthManager<TApp, TKey> manager)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            AllowOnlyAlphanumericUserNames = true;
            Manager = manager;
        }

        /// <summary>
        ///     Only allow [A-Za-z0-9@_] in UserNames
        /// </summary>
        public bool AllowOnlyAlphanumericUserNames { get; set; }

        private OAuthManager<TApp, TKey> Manager { get; set; }

        /// <summary>
        ///     Validates a user before saving
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public virtual async Task<IOperationResult> ValidateAsync(TApp item)
        {
            if (item == null)
            {
                throw new ArgumentNullException("item");
            }
            var errors = new List<string>();
            await ValidateUserName(item, errors).WithCurrentCulture();
            if (errors.Count > 0)
            {
                return OperationResult.Failed(errors.ToArray());
            }
            return OperationResult.Success;
        }

        private async Task ValidateUserName(TApp app, List<string> errors)
        {
            if (string.IsNullOrWhiteSpace(app.ClientName))
            {
                errors.Add(String.Format(CultureInfo.CurrentCulture, R.String.Get("PropertyTooShort"), "Name"));
            }
            else if (AllowOnlyAlphanumericUserNames && !Regex.IsMatch(app.ClientName, @"^[A-Za-z0-9@_\.]+$"))
            {
                // If any characters are not letters or digits, its an illegal user name
                errors.Add(String.Format(CultureInfo.CurrentCulture, R.String.Get("InvalidUserName"), app.ClientName));
            }
            else
            {
                var owner = await Manager.FindByNameAsync(app.ClientName).WithCurrentCulture();
                if (owner != null/* && !EqualityComparer<string>.Default.Equals(owner.Id, app.Id)*/)
                {
                    errors.Add(String.Format(CultureInfo.CurrentCulture, R.String.Get("DuplicateName"), app.ClientName));
                }
            }
        }
    }
}