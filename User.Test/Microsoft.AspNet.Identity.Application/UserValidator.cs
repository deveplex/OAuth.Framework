// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Identity;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

//namespace Microsoft.AspNet.Identity.Application
//{
//    /// <summary>
//    ///     Validates users before they are saved
//    /// </summary>
//    /// <typeparam name="TUser"></typeparam>
//    public class UserValidator<TUser> : IIdentityValidator<TUser, string> where TUser : class, IUser<string>
//    {
//        /// <summary>
//        ///     Constructor
//        /// </summary>
//        /// <param name="manager"></param>
//        public UserValidator(UserManager<TUser, string> manager)
//            : base(manager)
//        {
//            Manager = manager;
//        }

//        private UserManager<TUser, string> Manager { get; set; }

//        /// <summary>
//        ///     Validates a user before saving
//        /// </summary>
//        /// <param name="item"></param>
//        /// <returns></returns>
//        public override async Task<IdentityResult> ValidateAsync(TUser item)
//        {
//            if (item == null)
//            {
//                throw new ArgumentNullException("item");
//            }
//            var errors = new List<string>();
//            await ValidateUserName(item, errors).WithCurrentCulture();
//            if (RequireUniqueEmail)
//            {
//                await ValidateEmailAsync(item, errors).WithCurrentCulture();
//            }
//            if (errors.Count > 0)
//            {
//                return IdentityResult.Failed(errors.ToArray());
//            }
//            return IdentityResult.Success;
//        }

//        private async Task ValidateUserName(TUser user, List<string> errors)
//        {
//            if (string.IsNullOrWhiteSpace(user.UserName))
//            {
//                errors.Add(String.Format(CultureInfo.CurrentCulture, "PropertyTooShort{0}", "Name"));
//            }
//            else if (AllowOnlyAlphanumericUserNames && !Regex.IsMatch(user.UserName, @"^[A-Za-z0-9@_\.]+$"))
//            {
//                // If any characters are not letters or digits, its an illegal user name
//                errors.Add(String.Format(CultureInfo.CurrentCulture, "InvalidUserName{0}", user.UserName));
//            }
//            else
//            {
//                var owner = await Manager.FindByNameAsync(user.UserName).WithCurrentCulture();
//                if (owner != null && !EqualityComparer<string>.Default.Equals(owner.Id, user.Id))
//                {
//                    errors.Add(String.Format(CultureInfo.CurrentCulture, "DuplicateName{0}", user.UserName));
//                }
//            }
//        }

//        // make sure email is not empty, valid, and unique
//        private Task ValidateEmailAsync(TUser user, List<string> errors)
//        {
//            return Task.FromResult(0);
//            //var email = await Manager.GetEmailStore().GetEmailAsync(user).WithCurrentCulture();
//            //if (string.IsNullOrWhiteSpace(email))
//            //{
//            //    errors.Add(String.Format(CultureInfo.CurrentCulture, "Resources.PropertyTooShort{0}", "Email"));
//            //    return;
//            //}
//            //try
//            //{
//            //    var m = new MailAddress(email);
//            //}
//            //catch (FormatException)
//            //{
//            //    errors.Add(String.Format(CultureInfo.CurrentCulture, "Resources.InvalidEmail{0}", email));
//            //    return;
//            //}
//            //var owner = await Manager.FindByEmailAsync(email).WithCurrentCulture();
//            //if (owner != null && !EqualityComparer<TKey>.Default.Equals(owner.Id, user.Id))
//            //{
//            //    errors.Add(String.Format(CultureInfo.CurrentCulture, "Resources.DuplicateEmail{0}", email));
//            //}
//        }
//    }
//}