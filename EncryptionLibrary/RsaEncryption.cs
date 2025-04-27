using System;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionLibrary
{
    public class RsaEncryption
    {
        private readonly string _keyFolderPath;

        public RsaEncryption(string keyFolderPath)
        {
            _keyFolderPath = keyFolderPath;
            if (!Directory.Exists(_keyFolderPath))
            {
                Directory.CreateDirectory(_keyFolderPath);
            }
        }

        // Ophalen van alle public keys
        public string[] GetPublicKeys()
        {
            return Directory.GetFiles(_keyFolderPath, "*_PublicKey.xml");
        }

        // Ophalen van alle private keys
        public string[] GetPrivateKeys()
        {
            return Directory.GetFiles(_keyFolderPath, "*_PrivateKey.xml");
        }

        // Encryptie van data met een public key
        public static byte[] EncryptData(byte[] dataToEncrypt, string publicKeyPath)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA512);
            }
        }

        // Decryptie van data met een private key
        public static byte[] DecryptData(byte[] dataToDecrypt, string privateKeyPath)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(File.ReadAllText(privateKeyPath));
                return rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA512);
            }
        }
    }

    public static class AesKeyManager
    {
        public static byte[] LoadAesKey(string aesKeyPath)
        {
            return Convert.FromBase64String(File.ReadAllText(aesKeyPath));
        }

        public static void SaveEncryptedKey(byte[] encryptedKey, string savePath)
        {
            File.WriteAllText(savePath, Convert.ToBase64String(encryptedKey));
        }

        public static void SaveDecryptedKey(byte[] decryptedKey, string savePath)
        {
            File.WriteAllText(savePath, Convert.ToBase64String(decryptedKey));
        }
    }
}
