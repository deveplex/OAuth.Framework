// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Identity;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

//namespace Microsoft.AspNet.Identity.Application
//{
//    /// <summary>
//    ///     Used to validate some basic password policy like length and number of non alphanumerics
//    /// </summary>
//    public class PasswordValidator : IIdentityValidator<string>
//    {

//        /// <summary>
//        ///     Only allow Specific Regex in Password
//        /// </summary>
//        public bool AllowOnlyAlphanumericUserNames { get; set; }

//        /// <summary>
//        ///     Minimum required length
//        /// </summary>
//        public int RequiredLength { get; set; }

//        /// <summary>
//        ///     Require a non letter or digit character
//        /// </summary>
//        public bool RequireNonLetterOrDigit { get; set; }

//        /// <summary>
//        ///     Require a lower case letter ('a' - 'z')
//        /// </summary>
//        public bool RequireLowercase { get; set; }

//        /// <summary>
//        ///     Require an upper case letter ('A' - 'Z')
//        /// </summary>
//        public bool RequireUppercase { get; set; }

//        /// <summary>
//        ///     Require a digit ('0' - '9')
//        /// </summary>
//        public bool RequireDigit { get; set; }

//        /// <summary>
//        ///     Ensures that the string is of the required length and meets the configured requirements
//        /// </summary>
//        /// <param name="item"></param>
//        /// <returns></returns>
//        public virtual Task<IdentityResult> ValidateAsync(string item)
//        {
//            if (item == null)
//            {
//                throw new ArgumentNullException("item");
//            }

//            var errors = new List<string>();
//            ValidatePassword(item, errors).WithCurrentCulture();
//            if (errors.Count > 0)
//            {
//                return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
//            }
//            return Task.FromResult(IdentityResult.Success);
//        }

//        private Task ValidatePassword(string password, List<string> errors)
//        {

//            if (string.IsNullOrWhiteSpace(password))
//            {
//                errors.Add(String.Format(CultureInfo.CurrentCulture, "PropertyTooShort{0}", "Name"));
//            }
//            else if (AllowOnlyAlphanumericUserNames && !Regex.IsMatch(password, @"^[A-Za-z0-9@_\.]+$"))
//            {
//                errors.Add(String.Format(CultureInfo.CurrentCulture, "PasswordRequireNonLetterOrDigit"));
//            }
//            return Task.FromResult(0);
//        }
//    }
//}