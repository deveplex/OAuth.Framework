// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.AspNet.OAuth.Framework
{
    internal static class Crypto
    {
        private const int PBKDF2IterCount = 1000; // default for Rfc2898DeriveBytes
        private const int PBKDF2SubkeyLength = 256 / 8; // 256 bits
        private const int SaltSize = 128 / 8; // 128 bits

        /* =======================
         * HASHED PASSWORD FORMATS
         * =======================
         * 
         * Version 0:
         * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
         * (See also: SDL crypto guidelines v5.1, Part III)
         * Format: { 0x00, salt, subkey }
         */

        public static string Encrypt(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            byte[] salt = new byte[SaltSize] { 0x52, 0x86, 0x8D, 0xED, 0x0A, 0xBF, 0xC5, 0xA3, 0x28, 0x96, 0x03, 0x0C, 0xBA, 0x1F, 0x9D, 0xC6 };
            byte[] subkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                subkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return Convert.ToBase64String(subkey);
        }

        public static string Encrypt(string password, out string key)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            // Produce a version 0 (see comment above) text hash.
            byte[] salt;
            byte[] subkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, SaltSize, PBKDF2IterCount))
            {
                salt = deriveBytes.Salt;
                subkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            key = Convert.ToBase64String(salt);

            //var outputBytes = new byte[1 + SaltSize + PBKDF2SubkeyLength];
            //Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            //Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, PBKDF2SubkeyLength);
            return Convert.ToBase64String(subkey);
        }

        public static string Encrypt(string password, string key)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            if (key.Length < 8)
            {
                throw new ArgumentException("The key size must be 8 bytes and larger");
            }

            // Produce a version 0 (see comment above) text hash.
            byte[] salt = Convert.FromBase64String(key);
            byte[] subkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                subkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            //var outputBytes = new byte[1 + SaltSize + PBKDF2SubkeyLength];
            //Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            //Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, PBKDF2SubkeyLength);
            return Convert.ToBase64String(subkey);
        }
        /*
        public static string Encrypt(string password, out string key, out string iv)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            // Creates an RC2 object to encrypt with the derived key
            var rc2 = new RC2CryptoServiceProvider();
            key = rc2.GenerateKey();
            iv = rc2.GenerateIV();
            // Encrypts the data.
            byte[] plaintext = Encoding.UTF8.GetBytes(password);
            using (var ms = new MemoryStream())
            {
                var cs = new CryptoStream(
                    ms, rc2.CreateEncryptor(), CryptoStreamMode.Write);

                cs.Write(plaintext, 0, plaintext.Length);
                cs.Close();
                byte[] encrypted = ms.ToArray();
            }
            return Convert.ToBase64String(hashkey);

        }

        public static byte[] Decrypt(string hashedPassword)
        {
            if (hashedPassword == null)
            {
                return null;
            }

            var hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            // Verify a version 0 (see comment above) text hash.

            if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
            {
                // Wrong length or version header.
                return null;
            }


            var salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);
            var storedSubkey = new byte[PBKDF2SubkeyLength];
            Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);
            return storedSubkey;
        }
        */
        // hashedPassword must be of the format of HashWithPassword (salt + Hash(salt+input)
        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            if (hashedPassword == null)
            {
                return false;
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            // Verify a version 0 (see comment above) text hash.

            if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
            {
                // Wrong length or version header.
                return false;
            }

            var salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);
            var storedSubkey = new byte[PBKDF2SubkeyLength];
            Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);

            byte[] generatedSubkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return ByteArraysEqual(storedSubkey, generatedSubkey);
        }

        // Compares two byte arrays for equality. The method is specifically written so that the loop is not optimized.
        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }
    }
}