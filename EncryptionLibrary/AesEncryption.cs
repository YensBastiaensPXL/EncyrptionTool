using System;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionLibrary
{
    public static class AesEncryption
    {
        // Encrypteer een BINair bestand (.enc bijvoorbeeld)
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

        // Decrypteer een BINair bestand (.enc bijvoorbeeld)
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

        // Encrypteer naar een BASE64 tekstbestand (.txt bijvoorbeeld)
        public static void EncryptFileToBase64(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                byte[] fileBytes = File.ReadAllBytes(inputFile);

                byte[] encryptedBytes;
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(fileBytes, 0, fileBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    encryptedBytes = memoryStream.ToArray();
                }

                string base64String = Convert.ToBase64String(encryptedBytes);
                File.WriteAllText(outputFile, base64String);
            }
        }

        // Decrypteer van een BASE64 tekstbestand (.txt bijvoorbeeld)
        public static void DecryptBase64ToFile(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            string base64Content = File.ReadAllText(inputFile);
            byte[] encryptedBytes = Convert.FromBase64String(base64Content);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream memoryStream = new MemoryStream(encryptedBytes))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
                {
                    cryptoStream.CopyTo(outputStream);
                }
            }
        }
    }
}
