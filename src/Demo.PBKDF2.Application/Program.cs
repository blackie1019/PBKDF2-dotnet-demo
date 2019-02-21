using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Demo.PBKDF2.Application
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            var count = 10;
            var results = new Hashtable();
            
            for (var i = 0; i < count; i++)
            {
                var pw = $"PasswordPlainText:{i.ToString()}";
                var salt = CreateSalt();
                var dk = GenerateDk(pw,salt);

                results.Add(i.ToString(), $"Password={pw}, DK={dk}, Compare Result={Validate(pw,salt,dk).ToString()}");
            }

            foreach (var value in results.Values)
            {
                Console.WriteLine(value);
            }

            Console.ReadKey();

        }
        
        
        public static bool Validate(string pw, string salt, string hash)
            => GenerateDk(pw, salt) == hash;

        private static string GenerateDk(string pw,string salt)
        {
            var dk = KeyDerivation.Pbkdf2(
                password: pw,
                salt: Encoding.UTF8.GetBytes(salt),
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: 1000,
                numBytesRequested: 256 / 8);
            return  Convert.ToBase64String(dk);
        }
        
        private static string CreateSalt()
        {
            byte[] randomBytes = new byte[128 / 8];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(randomBytes);
                return Convert.ToBase64String(randomBytes);
            }
        }
    }
}