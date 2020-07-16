using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.Identity.Common
{
    public static class IdentityGenerator
    {
        public static string RandomUserNumeral20()
        {
            UInt64 minVal = 1000000000;
            UInt64 maxVal = 9999999999;
            UInt64 m1 = maxVal - minVal;
            UInt64 m2 = maxVal - 0;
            UInt64 _base = UInt64.MaxValue;
            byte[] randomBytes = new byte[16];
            System.Security.Cryptography.RNGCryptoServiceProvider rngServiceProvider = new System.Security.Cryptography.RNGCryptoServiceProvider();
            rngServiceProvider.GetBytes(randomBytes);
            decimal hRandom = BitConverter.ToUInt64(randomBytes, 0);
            decimal lRandom = BitConverter.ToUInt64(randomBytes, 8);
            string hResult = (minVal + (UInt64)(hRandom / _base * m1)).ToString("0000000000");
            string lResult = ((UInt64)(lRandom / _base * m2)).ToString("0000000000");
            return hResult + lResult;
        }
        public static string RandomUserName()
        {
            return RandomStringGenerator.RandomCharacter(3) + RandomStringGenerator.RandomNumber(8);
        }
        public static string RandomBase64String(int length)
        {
            byte[] data = new byte[length];
            new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(data);
            return Convert.ToBase64String(data);
        }
    }
    public static class RandomNumeralGenerator
    {
        public static string RandomNumeral20()
        {
            byte[] randomBytes = new byte[8];
            System.Security.Cryptography.RNGCryptoServiceProvider rngServiceProvider = new System.Security.Cryptography.RNGCryptoServiceProvider();
            rngServiceProvider.GetBytes(randomBytes);
            decimal random = BitConverter.ToUInt32(randomBytes, 0);
            var result = random.ToString("00000000000000000000");
            return result;
        }
        /// <summary>
        /// 生成随机数
        /// </summary>
        /// <param name="minVal">最小值（包含）</param>
        /// <param name="maxVal">最大值（不包含）</param>
        /// <returns></returns>
        public static decimal RandomNumeral(UInt64 minVal, UInt64 maxVal)
        {
            UInt64 m = maxVal - minVal;
            UInt64 _base = UInt64.MaxValue;
            byte[] randomBytes = new byte[8];
            System.Security.Cryptography.RNGCryptoServiceProvider rngServiceProvider = new System.Security.Cryptography.RNGCryptoServiceProvider();
            rngServiceProvider.GetBytes(randomBytes);
            decimal random = BitConverter.ToUInt64(randomBytes, 0);
            decimal result = minVal + (decimal)(random / _base * m);
            return result;
        }
    }
    public static class RandomStringGenerator
    {
        private static readonly char[] number =
        {
        '0','1','2','3','4','5','6','7','8','9',
        };
        private static readonly char[] character =
        {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'
        };
        private static readonly char[] punctuation =
        {
        '_'
        };
        public static string RandomCharacter(int length)
        {
            char[] constant = character;

            System.Text.StringBuilder newRandom = new System.Text.StringBuilder();
            Random rd = new Random();
            for (int i = 0; i < length; i++)
            {
                newRandom.Append(constant[rd.Next(constant.Length)]);
            }
            return newRandom.ToString();
        }
        public static string RandomNumber(int length)
        {
            char[] constant = number;

            System.Text.StringBuilder newRandom = new System.Text.StringBuilder();
            Random rd = new Random();
            for (int i = 0; i < length; i++)
            {
                newRandom.Append(constant[rd.Next(constant.Length)]);
            }
            return newRandom.ToString();
        }
        public static string RandomCharNumber(int length)
        {
            char[] constant = character.Concat(number).ToArray();

            System.Text.StringBuilder newRandom = new System.Text.StringBuilder();
            Random rd = new Random();
            for (int i = 0; i < length; i++)
            {
                newRandom.Append(constant[rd.Next(constant.Length)]);
            }
            return newRandom.ToString();
        }
    }
}
