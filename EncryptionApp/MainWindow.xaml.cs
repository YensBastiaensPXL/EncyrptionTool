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

        public MainWindow()
        {
            InitializeComponent();
            LoadDefaultKeyFolder();
            AesFrame.Navigate(new AesPage());
            RsaFrame.Navigate(new RsaPage());
        }

        private void LoadDefaultKeyFolder()
        {
            string defaultKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionKeys");
            if (!Directory.Exists(defaultKeyPath))
            {
                Directory.CreateDirectory(defaultKeyPath);
            }
            keyFolderPath = defaultKeyPath;
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
    }
}
