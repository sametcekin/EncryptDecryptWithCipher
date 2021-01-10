using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace EncryptDecryptWithCipher
{
    public static class SHA512
    {
        public static void CreateHash(string input, out byte[] inputHash, out byte[] inputSalt)
        {
            if (input == null)
                throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");

            using (var hmac = new HMACSHA512())
            {
                inputSalt = hmac.Key;
                inputHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        public static bool VerifyHash(string input, byte[] storedHash, byte[] storedSalt)
        {
            if (input == null)
                throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException("Value cannot be empty or whitespace only string.", "input");
            if (storedHash.Length != 64)
                throw new ArgumentException("Invalid length of password hash (64 bytes expected).", "inputHash");
            if (storedSalt.Length != 128)
                throw new ArgumentException("Invalid length of password salt (128 bytes expected).", "inputHash");

            using (var hmac = new HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i]) return false;
                }
            }

            return true;
        }
    }
}
