using EncryptionLibrary;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using MessageBox = System.Windows.MessageBox;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace EncryptionApp
{
    public partial class RsaPage : Page
    {
        private readonly RsaEncryption rsaKeyManager;
        private string selectedPublicKeyPath;
        private string selectedPrivateKeyPath;
        private string selectedPlaintextAESKeyPath;
        private string selectedCiphertextAESKeyPath;
        private string ciphertextFolderPath;

        public RsaPage()
        {
            InitializeComponent();

            rsaKeyManager = new RsaEncryption(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionKeys"));
            LoadPublicAndPrivateKeys();
        }

        private void LoadPublicAndPrivateKeys()
        {
            PublicKeyListBox.ItemsSource = rsaKeyManager.GetPublicKeys();
            PrivateKeyListBox.ItemsSource = rsaKeyManager.GetPrivateKeys();
        }

        private void PublicKeyListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PublicKeyListBox.SelectedItem != null)
                selectedPublicKeyPath = PublicKeyListBox.SelectedItem.ToString();
        }

        private void PrivateKeyListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PrivateKeyListBox.SelectedItem != null)
                selectedPrivateKeyPath = PrivateKeyListBox.SelectedItem.ToString();
        }

        private void SelectPlaintextAESKey_Click(object sender, RoutedEventArgs e)
        {
            selectedPlaintextAESKeyPath = SelectFile("Text Files (*.txt)|*.txt");
        }

        private void SelectCiphertextAESKey_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(ciphertextFolderPath))
            {
                MessageBox.Show("Stel eerst de standaard ciphertext-folder in.", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new OpenFileDialog
            {
                InitialDirectory = ciphertextFolderPath,
                Filter = "Text- en XML-bestanden (*.txt;*.xml)|*.txt;*.xml"

            };

            if (dialog.ShowDialog() == true)
                selectedCiphertextAESKeyPath = dialog.FileName;
        }

        private void EncryptAESKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(selectedPublicKeyPath) || string.IsNullOrEmpty(selectedPlaintextAESKeyPath) || string.IsNullOrEmpty(ciphertextFolderPath))
                {
                    MessageBox.Show("Selecteer eerst een public key, een plaintext AES key en stel een ciphertext-folder in.", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                byte[] aesKey = AesKeyManager.LoadAesKey(selectedPlaintextAESKeyPath);
                byte[] encryptedKey = RsaEncryption.EncryptData(aesKey, selectedPublicKeyPath);

                var saveDialog = new SaveFileDialog
                {
                    Title = "Kies waar je de versleutelde AES sleutel wilt opslaan",
                    Filter = "Text Files (*.txt)|*.txt",
                    InitialDirectory = ciphertextFolderPath
                };

                if (saveDialog.ShowDialog() == true)
                {
                    AesKeyManager.SaveEncryptedKey(encryptedKey, saveDialog.FileName);
                    MessageBox.Show("AES sleutel succesvol geëncrypt en opgeslagen.", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);
                    LoadCiphertextFiles();
                }
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Cryptografische fout: verkeerde public key gebruikt bij encryptie.", "Encryptie Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij encryptie: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DecryptAESKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(selectedPrivateKeyPath) || string.IsNullOrEmpty(selectedCiphertextAESKeyPath) || string.IsNullOrEmpty(ciphertextFolderPath))
                {
                    MessageBox.Show("Selecteer eerst een private key, een ciphertext AES key en stel een ciphertext-folder in.", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                byte[] encryptedKey = AesKeyManager.LoadAesKey(selectedCiphertextAESKeyPath);
                byte[] decryptedKey = RsaEncryption.DecryptData(encryptedKey, selectedPrivateKeyPath);

                var saveDialog = new SaveFileDialog
                {
                    Title = "Kies waar je de gedecrypteerde AES sleutel wilt opslaan",
                    Filter = "Text Files (*.txt)|*.txt",
                    InitialDirectory = ciphertextFolderPath
                };

                if (saveDialog.ShowDialog() == true)
                {
                    AesKeyManager.SaveDecryptedKey(decryptedKey, saveDialog.FileName);
                    MessageBox.Show("AES sleutel succesvol gedecrypt en opgeslagen.", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);
                    LoadCiphertextFiles();
                }
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Cryptografische fout: verkeerde private key gebruikt bij decryptie.", "Decryptie Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij decryptie: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SetCiphertextFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new FolderBrowserDialog();
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                ciphertextFolderPath = dialog.SelectedPath;
                MessageBox.Show($"Standaard ciphertext-folder ingesteld:\n{ciphertextFolderPath}", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);

                LoadCiphertextFiles();
            }
        }

        private void LoadCiphertextFiles_Click(object sender, RoutedEventArgs e)
        {
            LoadCiphertextFiles();
        }

        private void LoadCiphertextFiles()
        {
            if (string.IsNullOrEmpty(ciphertextFolderPath))
            {
                CiphertextListBox.ItemsSource = null;
                return;
            }

            string[] files = CiphertextManager.LoadCiphertextFiles(ciphertextFolderPath);
            CiphertextListBox.ItemsSource = files;
        }

        private string SelectFile(string filter)
        {
            var dialog = new OpenFileDialog { Filter = filter };
            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }
    }
}
