﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Net
{
    /// <summary>
    ///     Represents the result of an operation
    /// </summary>
    public interface IOperationResult
    {
        //private static readonly IdentityResult _success = new IdentityResult(true);

        ///// <summary>
        /////     Failure constructor that takes error messages
        ///// </summary>
        ///// <param name="errors"></param>
        //public IdentityResult(params string[] errors) : this((IEnumerable<string>)errors)
        //{
        //}

        ///// <summary>
        /////     Failure constructor that takes error messages
        ///// </summary>
        ///// <param name="errors"></param>
        //public IdentityResult(IEnumerable<string> errors)
        //{
        //    if (errors == null)
        //    {
        //        errors = new[] { Resources.DefaultError };
        //    }
        //    Succeeded = false;
        //    Errors = errors;
        //}

        ///// <summary>
        ///// Constructor that takes whether the result is successful
        ///// </summary>
        ///// <param name="success"></param>
        //protected IdentityResult(bool success)
        //{
        //    Succeeded = success;
        //    Errors = new string[0];
        //}

        /// <summary>
        ///     True if the operation was successful
        /// </summary>
        bool Succeeded { get; }

        /// <summary>
        ///     List of errors
        /// </summary>
        IEnumerable<string> Errors { get; }

        ///// <summary>
        /////     Static success result
        ///// </summary>
        ///// <returns></returns>
        //public static IdentityResult Success
        //{
        //    get { return _success; }
        //}

        ///// <summary>
        /////     Failed helper method
        ///// </summary>
        ///// <param name="errors"></param>
        ///// <returns></returns>
        //public static IdentityResult Failed(params string[] errors)
        //{
        //    return new IdentityResult(errors);
        //}
    }
}
