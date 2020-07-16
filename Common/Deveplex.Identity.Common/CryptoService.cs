using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.Identity.Security
{
    public static class CryptoService
    {
        //16字节,128位
        public static string MD5(string str)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(str);
            MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider();
            byte[] byteArr = MD5.ComputeHash(buffer);
            return BitConverter.ToString(byteArr);
        }


        //20字节,160位
        public static string SHA128(string str)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(str);
            SHA1CryptoServiceProvider SHA1 = new SHA1CryptoServiceProvider();
            byte[] byteArr = SHA1.ComputeHash(buffer);
            return BitConverter.ToString(byteArr);
        }


        //32字节,256位
        public static string HashCheckCode(string str)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(str);
            SHA256CryptoServiceProvider SHA256 = new SHA256CryptoServiceProvider();
            byte[] byteArr = SHA256.ComputeHash(buffer);
            return BitConverter.ToString(byteArr).Replace("-", "");
        }


        //48字节,384位
        public static string SHA384(string str)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(str);
            SHA384CryptoServiceProvider SHA384 = new SHA384CryptoServiceProvider();
            byte[] byteArr = SHA384.ComputeHash(buffer);
            return BitConverter.ToString(byteArr);
        }

        //64字节,512位
        public static string PasswordCrypto(string str)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(str);
            SHA512CryptoServiceProvider SHA512 = new SHA512CryptoServiceProvider();
            byte[] byteArr = SHA512.ComputeHash(buffer);
            return Convert.ToBase64String(byteArr);
        }
    }
}
