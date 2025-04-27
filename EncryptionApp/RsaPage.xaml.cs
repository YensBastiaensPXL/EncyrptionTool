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
        private readonly RsaEncryption rsaManager;
        private string selectedPublicKeyPath;
        private string selectedPrivateKeyPath;
        private string selectedPlaintextAESKeyPath;
        private string selectedCiphertextAESKeyPath;
        private string ciphertextFolderPath;

        public RsaPage()
        {
            InitializeComponent();
            rsaManager = new RsaEncryption(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionKeys"));
            LoadKeys();
        }

        private void LoadKeys()
        {
            PublicKeyListBox.ItemsSource = rsaManager.GetPublicKeys();
            PrivateKeyListBox.ItemsSource = rsaManager.GetPrivateKeys();
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

        private void SetCiphertextFolder_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new FolderBrowserDialog())
            {
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    ciphertextFolderPath = dialog.SelectedPath;
                    MessageBox.Show($"Ciphertext folder ingesteld: {ciphertextFolderPath}");
                    LoadCiphertextFiles();
                }
            }
        }

        private void SelectPlaintextAESKey_Click(object sender, RoutedEventArgs e)
        {
            selectedPlaintextAESKeyPath = SelectFile("Text Files (*.txt)|*.txt");
        }

        private void SelectCiphertextAESKey_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(ciphertextFolderPath))
            {
                MessageBox.Show("Stel eerst de ciphertext folder in.", "Fout");
                return;
            }

            var dialog = new OpenFileDialog
            {
                InitialDirectory = ciphertextFolderPath,
                Filter = "Text Files (*.txt)|*.txt"
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
                    MessageBox.Show("Selecteer public key, AES plaintext bestand en ciphertext folder.");
                    return;
                }

                byte[] aesKey = AesKeyManager.LoadAesKey(selectedPlaintextAESKeyPath);
                byte[] encryptedKey = RsaEncryption.EncryptData(aesKey, selectedPublicKeyPath);

                var saveDialog = new SaveFileDialog
                {
                    Title = "Opslaan versleutelde AES sleutel",
                    Filter = "Text Files (*.txt)|*.txt",
                    InitialDirectory = ciphertextFolderPath
                };

                if (saveDialog.ShowDialog() == true)
                {
                    AesKeyManager.SaveEncryptedKey(encryptedKey, saveDialog.FileName);
                    MessageBox.Show("AES sleutel succesvol versleuteld en opgeslagen!");
                    LoadCiphertextFiles();
                }
            }
            catch (CryptographicException cx)
            {
                MessageBox.Show($"Cryptografische fout tijdens encryptie: {cx.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
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
                if (string.IsNullOrEmpty(selectedPrivateKeyPath) || string.IsNullOrEmpty(selectedCiphertextAESKeyPath))
                {
                    MessageBox.Show("Selecteer private key en ciphertext bestand.");
                    return;
                }

                byte[] encryptedKey = AesKeyManager.LoadAesKey(selectedCiphertextAESKeyPath);
                byte[] decryptedKey = RsaEncryption.DecryptData(encryptedKey, selectedPrivateKeyPath);

                var saveDialog = new SaveFileDialog
                {
                    Title = "Opslaan gedecrypteerde AES sleutel",
                    Filter = "Text Files (*.txt)|*.txt",
                    InitialDirectory = ciphertextFolderPath
                };

                if (saveDialog.ShowDialog() == true)
                {
                    AesKeyManager.SaveDecryptedKey(decryptedKey, saveDialog.FileName);
                    MessageBox.Show("AES sleutel succesvol gedecrypt en opgeslagen!");
                    LoadCiphertextFiles();
                }
            }
            catch (CryptographicException cx)
            {
                MessageBox.Show($"Cryptografische fout tijdens decryptie: {cx.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij decryptie: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadCiphertextFiles()
        {
            if (string.IsNullOrEmpty(ciphertextFolderPath)) return;
            CiphertextListBox.ItemsSource = CiphertextManager.LoadCiphertextFiles(ciphertextFolderPath);
        }

        private string SelectFile(string filter)
        {
            var dialog = new OpenFileDialog { Filter = filter };
            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }
    }
}
