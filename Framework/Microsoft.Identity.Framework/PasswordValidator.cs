﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Microsoft.Identity
{
    /// <summary>
    ///     Used to validate some basic password policy like length and number of non alphanumerics
    /// </summary>
    internal class PasswordValidator : IIdentityValidator<string>
    {
        /// <summary>
        ///     Ensures that the string is of the required length and meets the configured requirements
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public virtual Task<IdentityResult> ValidateAsync(string item)
        {
            if (item == null)
            {
                throw new ArgumentNullException("item");
            }
            var errors = new List<string>();
            ValidatePassword(item, errors);
            if (errors.Count > 0)
            {
                return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
            }
            return Task.FromResult(IdentityResult.Success);
        }

        private Task ValidatePassword(string password, List<string> errors)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                errors.Add(String.Format(CultureInfo.CurrentCulture, R.String.Get("PasswordTooShort")));
            }
            else if (!Regex.IsMatch(password, @"^[\S]{6,}$"))
            {
                errors.Add(String.Format(CultureInfo.CurrentCulture, R.String.Get("InvalidPassword"), password));
            }

            return Task.FromResult(0);
        }
    }
}