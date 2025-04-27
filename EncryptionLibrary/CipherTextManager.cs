using System.IO;

namespace EncryptionLibrary
{
    public class CiphertextManager
    {
        public static string[] LoadCiphertextFiles(string folderPath)
        {
            if (!Directory.Exists(folderPath))
                return new string[0];

            // Alleen .txt bestanden ophalen
            return Directory.GetFiles(folderPath, "*.txt");
        }
    }
}
