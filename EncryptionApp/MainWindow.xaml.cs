using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;

namespace EncryptionApp
{
    public partial class MainWindow : Window
    {
        private string keyFolderPath;
        private string selectedAESKeyName = "";
        private string selectedFileToDecrypt = "";
        private string selectedFileToEncrypt = "";

        public MainWindow()
        {
            InitializeComponent();
            LoadDefaultKeyFolder();
        }


        private void LoadDefaultKeyFolder()
        {
            string defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionKeys");
            if (!Directory.Exists(defaultPath))
            {
                Directory.CreateDirectory(defaultPath);
            }
            keyFolderPath = defaultPath;
        }

        private void SetKeyFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CommonOpenFileDialog
            {
                IsFolderPicker = true
            };

            if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
            {
                keyFolderPath = dialog.FileName;
                MessageBox.Show($"Standaard sleutelopslaglocatie ingesteld op: {keyFolderPath}");
            }
        }

        private void GenerateAESKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(keyFolderPath))
                {
                    MessageBox.Show("Stel eerst een standaard opslagmap in!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(KeyNameInput.Text))
                {
                    MessageBox.Show("Geef een naam op voor de sleutel!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string keyName = KeyNameInput.Text.Trim();

                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.GenerateKey();
                    aes.GenerateIV();

                    string keyBase64 = Convert.ToBase64String(aes.Key);
                    string ivBase64 = Convert.ToBase64String(aes.IV);

                    string keyFilePath = Path.Combine(keyFolderPath, $"{keyName}_AES_Key.txt");
                    string ivFilePath = Path.Combine(keyFolderPath, $"{keyName}_AES_IV.txt");

                    File.WriteAllText(keyFilePath, keyBase64);
                    File.WriteAllText(ivFilePath, ivBase64);

                    MessageBox.Show($"AES-sleutel en IV opgeslagen als '{keyName}' in:\n{keyFolderPath}", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het genereren van de AES-sleutel: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void GenerateRSAKeyPair_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(keyFolderPath))
                {
                    MessageBox.Show("Stel eerst een standaard opslagmap in!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(KeyNameInput.Text))
                {
                    MessageBox.Show("Geef een naam op voor de sleutel!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string keyName = KeyNameInput.Text.Trim();

                using (RSA rsa = RSA.Create())
                {
                    rsa.KeySize = 2048;

                    string publicKeyXml = rsa.ToXmlString(false);
                    string privateKeyXml = rsa.ToXmlString(true);

                    string publicKeyPath = Path.Combine(keyFolderPath, $"{keyName}_PublicKey.xml");
                    string privateKeyPath = Path.Combine(keyFolderPath, $"{keyName}_PrivateKey.xml");

                    File.WriteAllText(publicKeyPath, publicKeyXml);
                    File.WriteAllText(privateKeyPath, privateKeyXml);

                    MessageBox.Show($"RSA-sleutelpaar opgeslagen als '{keyName}' in:\n{keyFolderPath}", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het genereren van de RSA-sleutel: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadAESKeys_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                AESKeyListBox.Items.Clear(); // Maak de lijst leeg voor een nieuwe laadactie.

                if (string.IsNullOrEmpty(keyFolderPath) || !Directory.Exists(keyFolderPath))
                {
                    MessageBox.Show("Stel eerst een standaard sleutelmap in!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string[] keyFiles = Directory.GetFiles(keyFolderPath, "*_AES_Key.txt");

                if (keyFiles.Length == 0)
                {
                    MessageBox.Show("Geen AES-sleutels gevonden!", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                foreach (string file in keyFiles)
                {
                    string fileName = Path.GetFileNameWithoutExtension(file).Replace("_AES_Key", "");
                    AESKeyListBox.Items.Add(fileName);
                }

                MessageBox.Show($"Aantal gevonden sleutels: {AESKeyListBox.Items.Count}", "Debug", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het laden van AES-sleutels: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        private void SelectAESKey_Click(object sender, RoutedEventArgs e)
        {
            if (AESKeyListBox.SelectedItem == null)
            {
                MessageBox.Show("Selecteer een sleutel uit de lijst!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            selectedAESKeyName = AESKeyListBox.SelectedItem.ToString();
            selectedFileToDecrypt = ""; // Reset bestand om conflicts te voorkomen.
            MessageBox.Show($"AES sleutel geselecteerd: {selectedAESKeyName}", "Debug", MessageBoxButton.OK, MessageBoxImage.Information);
            SelectedAESKeyLabel.Text = $"🔍 Geselecteerde sleutel: {selectedAESKeyName}";
        }

        private void SelectFileToEncrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = "Selecteer een bestand om te encrypten",
                Filter = "Afbeeldingen (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg|Alle bestanden (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                selectedFileToEncrypt = openFileDialog.FileName;
                MessageBox.Show($"Geselecteerd bestand: {selectedFileToEncrypt}", "Bestand Gekozen", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void EncryptFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(selectedAESKeyName))
                {
                    MessageBox.Show("Selecteer een AES-sleutel uit de lijst!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(selectedFileToEncrypt) || !File.Exists(selectedFileToEncrypt))
                {
                    MessageBox.Show("Selecteer een geldig bestand om te encrypten!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Laad de AES-sleutel en IV
                string keyFilePath = Path.Combine(keyFolderPath, $"{selectedAESKeyName}_AES_Key.txt");
                string ivFilePath = Path.Combine(keyFolderPath, $"{selectedAESKeyName}_AES_IV.txt");

                if (!File.Exists(keyFilePath) || !File.Exists(ivFilePath))
                {
                    MessageBox.Show("AES-sleutel of IV ontbreekt in de sleutelmap!", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                byte[] key = Convert.FromBase64String(File.ReadAllText(keyFilePath));
                byte[] iv = Convert.FromBase64String(File.ReadAllText(ivFilePath));

                string encryptedFilePath = selectedFileToEncrypt + ".enc";

                // Voer de encryptie uit
                EncryptFiles(selectedFileToEncrypt, encryptedFilePath, key, iv);

                MessageBox.Show($"Bestand succesvol geëncrypt!\nOpgeslagen als: {encryptedFilePath}", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het encrypten: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void EncryptFiles(string inputFilePath, string outputFilePath, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open))
                using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create))
                using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    inputFileStream.CopyTo(cryptoStream);
                }
            }
        }

        private void SelectFileToDecrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = "Selecteer een bestand om te decrypten",
                Filter = "Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                selectedFileToDecrypt = openFileDialog.FileName;
                MessageBox.Show($"Geselecteerd bestand: {selectedFileToDecrypt}", "Bestand Gekozen", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        private void DecryptFiles(string inputFilePath, string outputFilePath, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open))
                using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create))
                using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outputFileStream);
                }
            }
        }

        private void DecryptFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(selectedAESKeyName))
                {
                    MessageBox.Show("Selecteer een AES-sleutel uit de lijst!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(selectedFileToDecrypt) || !File.Exists(selectedFileToDecrypt))
                {
                    MessageBox.Show("Selecteer een geldig bestand om te decrypten!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Laad de AES-sleutel en IV uit bestanden
                string keyFilePath = Path.Combine(keyFolderPath, $"{selectedAESKeyName}_AES_Key.txt");
                string ivFilePath = Path.Combine(keyFolderPath, $"{selectedAESKeyName}_AES_IV.txt");

                if (!File.Exists(keyFilePath) || !File.Exists(ivFilePath))
                {
                    MessageBox.Show("AES-sleutel of IV ontbreekt in de sleutelmap!", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                byte[] key = Convert.FromBase64String(File.ReadAllText(keyFilePath));
                byte[] iv = Convert.FromBase64String(File.ReadAllText(ivFilePath));

                string decryptedFilePath = selectedFileToDecrypt.Replace(".enc", "_decrypted.png");

                // Voer de decryptie uit
                DecryptFiles(selectedFileToDecrypt, decryptedFilePath, key, iv);

                MessageBox.Show($"Bestand succesvol gedecrypt!\nOpgeslagen als: {decryptedFilePath}", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het decrypten: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

}
