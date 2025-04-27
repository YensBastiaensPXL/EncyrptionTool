using EncryptionLibrary; // <== BELANGRIJK: je library importeren
using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;

namespace EncryptionApp
{
    public partial class AesPage : Page
    {
        private string keyFolderPath;
        private string ciphertextFolderPath;
        private string plaintextFolderPath;
        private string selectedAESKeyName = "";
        private string selectedFileToEncrypt = "";
        private string selectedFileToDecrypt = "";

        public AesPage()
        {
            InitializeComponent();
            LoadDefaultFolders();
        }

        private void LoadDefaultFolders()
        {
            string documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            keyFolderPath = Path.Combine(documents, "EncryptionKeys");
            Directory.CreateDirectory(keyFolderPath);

            ciphertextFolderPath = Path.Combine(documents, "Ciphertext");
            Directory.CreateDirectory(ciphertextFolderPath);

            plaintextFolderPath = Path.Combine(documents, "Plaintext");
            Directory.CreateDirectory(plaintextFolderPath);

            CiphertextFolderLabel.Text = $"📁 Ciphertext map: {ciphertextFolderPath}";
            PlaintextFolderLabel.Text = $"📁 Plaintext map: {plaintextFolderPath}";
        }

        private void SetCiphertextFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CommonOpenFileDialog { IsFolderPicker = true };
            if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
            {
                ciphertextFolderPath = dialog.FileName;
                CiphertextFolderLabel.Text = $"📁 Ciphertext map: {ciphertextFolderPath}";
                LoadCiphertextFiles_Click(sender, e);
            }
        }

        private void SetPlaintextFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CommonOpenFileDialog { IsFolderPicker = true };
            if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
            {
                plaintextFolderPath = dialog.FileName;
                PlaintextFolderLabel.Text = $"📁 Plaintext map: {plaintextFolderPath}";
            }
        }

        private void LoadAESKeys_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                AESKeyListBox.Items.Clear();

                if (!Directory.Exists(keyFolderPath))
                {
                    MessageBox.Show("Sleutelmap niet gevonden!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string[] keyFiles = Directory.GetFiles(keyFolderPath, "*_AES_Key.txt");
                foreach (string file in keyFiles)
                {
                    string name = Path.GetFileNameWithoutExtension(file).Replace("_AES_Key", "");
                    AESKeyListBox.Items.Add(name);
                }

                MessageBox.Show($"Aantal sleutels gevonden: {AESKeyListBox.Items.Count}", "Info");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het laden van sleutels: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SelectAESKey_Click(object sender, RoutedEventArgs e)
        {
            if (AESKeyListBox.SelectedItem == null)
            {
                MessageBox.Show("Selecteer een sleutel!", "Fout");
                return;
            }

            selectedAESKeyName = AESKeyListBox.SelectedItem.ToString();
            SelectedAESKeyLabel.Text = $"🔍 Geselecteerde sleutel: {selectedAESKeyName}";
        }

        private void SelectFileToEncrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog
            {
                Title = "Selecteer bestand",
                Filter = "Afbeeldingen (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg|Alle bestanden (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                selectedFileToEncrypt = dialog.FileName;
                SelectedEncryptFileLabel.Text = $"📝 Geselecteerd bestand: {Path.GetFileName(selectedFileToEncrypt)}";
                EncryptOutputFilename.Text = $"{Path.GetFileNameWithoutExtension(selectedFileToEncrypt)}.txt";
            }
        }

        private void EncryptFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(selectedAESKeyName)) throw new Exception("Geen AES sleutel geselecteerd!");
                if (string.IsNullOrEmpty(selectedFileToEncrypt)) throw new Exception("Geen bestand geselecteerd!");
                if (string.IsNullOrWhiteSpace(EncryptOutputFilename.Text)) throw new Exception("Geen output naam opgegeven!");

                byte[] key = LoadKey(selectedAESKeyName);
                byte[] iv = LoadIV(selectedAESKeyName);
                string outputPath = Path.Combine(ciphertextFolderPath, EncryptOutputFilename.Text.Trim());

                AesEncryption.EncryptFileToBase64(selectedFileToEncrypt, outputPath, key, iv);

                MessageBox.Show("Encryptie voltooid!", "Succes");
                LoadCiphertextFiles_Click(sender, e);
            }
            catch (CryptographicException cx)
            {
                MessageBox.Show($"Cryptografische fout: {cx.Message}\nMogelijk verkeerde sleutel!", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij encryptie: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SelectFileToDecrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog
            {
                Title = "Selecteer ciphertext",
                Filter = "Tekstbestanden (*.txt)|*.txt|Encrypted Files (*.enc)|*.enc|Alle bestanden (*.*)|*.*",
                InitialDirectory = ciphertextFolderPath
            };

            if (dialog.ShowDialog() == true)
            {
                selectedFileToDecrypt = dialog.FileName;
                SelectedDecryptFileLabel.Text = $"📝 Geselecteerd bestand: {Path.GetFileName(selectedFileToDecrypt)}";
                DecryptOutputFilename.Text = $"{Path.GetFileNameWithoutExtension(selectedFileToDecrypt)}_decrypted.png";
            }
        }

        private void DecryptFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (CheckDecryptionInputs())
                {
                    byte[] key = LoadKey(selectedAESKeyName);
                    byte[] iv = LoadIV(selectedAESKeyName);

                    string outputFile = Path.Combine(plaintextFolderPath, DecryptOutputFilename.Text.Trim());

                    if (Path.GetExtension(selectedFileToDecrypt).ToLower() == ".enc")
                        AesEncryption.DecryptFile(selectedFileToDecrypt, outputFile, key, iv);
                    else
                        AesEncryption.DecryptBase64ToFile(selectedFileToDecrypt, outputFile, key, iv);

                    MessageBox.Show("Decryptie voltooid!", "Succes");
                }
            }
            catch (CryptographicException cx)
            {
                MessageBox.Show($"Cryptografische fout: {cx.Message}\nMogelijk verkeerde sleutel!", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij decryptie: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadCiphertextFiles_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CiphertextListBox.Items.Clear();

                if (!Directory.Exists(ciphertextFolderPath))
                {
                    MessageBox.Show("Ciphertext map niet gevonden!", "Fout");
                    return;
                }

                foreach (string file in Directory.GetFiles(ciphertextFolderPath, "*.*"))
                {
                    if (file.EndsWith(".txt") || file.EndsWith(".enc"))
                        CiphertextListBox.Items.Add(Path.GetFileName(file));
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij laden ciphertext: {ex.Message}", "Fout");
            }
        }



        private byte[] LoadKey(string keyName)
        {
            string path = Path.Combine(keyFolderPath, $"{keyName}_AES_Key.txt");
            return Convert.FromBase64String(File.ReadAllText(path));
        }

        private byte[] LoadIV(string keyName)
        {
            string path = Path.Combine(keyFolderPath, $"{keyName}_AES_IV.txt");
            return Convert.FromBase64String(File.ReadAllText(path));


        }

        private bool CheckEncryptionInputs()
        {
            if (string.IsNullOrEmpty(selectedAESKeyName) || string.IsNullOrEmpty(selectedFileToEncrypt) || string.IsNullOrEmpty(EncryptOutputFilename.Text))
            {
                MessageBox.Show("Vul alles correct in voor encryptie!", "Fout");
                return false;
            }
            return true;
        }

        private bool CheckDecryptionInputs()
        {
            if (string.IsNullOrEmpty(selectedAESKeyName) || string.IsNullOrEmpty(selectedFileToDecrypt) || string.IsNullOrEmpty(DecryptOutputFilename.Text))
            {
                MessageBox.Show("Vul alles correct in voor decryptie!", "Fout");
                return false;
            }
            return true;
        }
    }
}
