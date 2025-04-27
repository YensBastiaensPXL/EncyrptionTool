using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace EncryptionLibrary
{
    public class KeyStorage
    {
        public string KeyFolderPath { get; private set; }

        public KeyStorage(string path)
        {
            KeyFolderPath = path;
            if (!Directory.Exists(KeyFolderPath))
            {
                Directory.CreateDirectory(KeyFolderPath);
            }
        }

        public void SaveKey(string fileName, string data)
        {
            File.WriteAllText(Path.Combine(KeyFolderPath, fileName), data);
        }

        public string LoadKey(string fileName)
        {
            return File.ReadAllText(Path.Combine(KeyFolderPath, fileName));
        }

        // Methode om een AES-sleutel te genereren en op te slaan
        public void GenerateAesKey(string keyName)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;  // Kies voor een sterke sleutelgrootte
                aes.GenerateKey();
                aes.GenerateIV();

                string keyBase64 = Convert.ToBase64String(aes.Key);
                string ivBase64 = Convert.ToBase64String(aes.IV);

                SaveKey($"{keyName}_AES_Key.txt", keyBase64);
                SaveKey($"{keyName}_AES_IV.txt", ivBase64);
            }
        }

        public string[] ListKeys(string filter)
        {
            return Directory.GetFiles(KeyFolderPath, filter + "*")
                            .Select(Path.GetFileNameWithoutExtension)
                            .ToArray();
        }
    }
}
