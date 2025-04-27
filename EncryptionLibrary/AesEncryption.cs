using System.IO;
using System.Security.Cryptography;

namespace EncryptionLibrary
{
    public class AesEncryption
    {
        public static void EncryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var outStream = new FileStream(outputFile, FileMode.Create))
                using (var inStream = new FileStream(inputFile, FileMode.Open))
                using (var cryptoStream = new CryptoStream(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    inStream.CopyTo(cryptoStream);
                }
            }
        }

        public static void DecryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var outStream = new FileStream(outputFile, FileMode.Create))
                using (var inStream = new FileStream(inputFile, FileMode.Open))
                using (var cryptoStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outStream);
                }
            }
        }
    }
}
