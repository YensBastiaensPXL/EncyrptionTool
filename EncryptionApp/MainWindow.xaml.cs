using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System;

namespace EncryptionApp
{
    public partial class MainWindow : Window
    {
        private string keyFolderPath;
        private string ciphertextFolderPath;
        private string plaintextFolderPath;
        private string selectedAESKeyName = "";
        private string selectedFileToDecrypt = "";
        private string selectedFileToEncrypt = "";
        private string selectedCiphertextFile = "";

        public MainWindow()
        {
            InitializeComponent();
<<<<<<< HEAD
            LoadDefaultKeyFolder();
            RsaFrame.Navigate(new RsaPage());
=======
            LoadDefaultFolders();
>>>>>>> 216897ceb3a6929012377fcef0131f8e22f23539
        }

        private void LoadDefaultFolders()
        {
            // Default key folder
            string defaultKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionKeys");
            if (!Directory.Exists(defaultKeyPath))
            {
                Directory.CreateDirectory(defaultKeyPath);
            }
            keyFolderPath = defaultKeyPath;

            // Default ciphertext folder
            string defaultCiphertextPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Ciphertext");
            if (!Directory.Exists(defaultCiphertextPath))
            {
                Directory.CreateDirectory(defaultCiphertextPath);
            }
            ciphertextFolderPath = defaultCiphertextPath;
            CiphertextFolderLabel.Text = $"📁 Ciphertext map: {ciphertextFolderPath}";

            // Default plaintext folder
            string defaultPlaintextPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Plaintext");
            if (!Directory.Exists(defaultPlaintextPath))
            {
                Directory.CreateDirectory(defaultPlaintextPath);
            }
            plaintextFolderPath = defaultPlaintextPath;
            PlaintextFolderLabel.Text = $"📁 Plaintext map: {plaintextFolderPath}";
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

        private void SetCiphertextFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CommonOpenFileDialog
            {
                IsFolderPicker = true
            };

            if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
            {
                ciphertextFolderPath = dialog.FileName;
                CiphertextFolderLabel.Text = $"📁 Ciphertext map: {ciphertextFolderPath}";
                MessageBox.Show($"Standaard ciphertext-folder ingesteld op: {ciphertextFolderPath}");
                LoadCiphertextFiles_Click(sender, e);
            }
        }

        private void SetPlaintextFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CommonOpenFileDialog
            {
                IsFolderPicker = true
            };

            if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
            {
                plaintextFolderPath = dialog.FileName;
                PlaintextFolderLabel.Text = $"📁 Plaintext map: {plaintextFolderPath}";
                MessageBox.Show($"Standaard plaintext-folder ingesteld op: {plaintextFolderPath}");
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

                MessageBox.Show($"Aantal gevonden sleutels: {AESKeyListBox.Items.Count}", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
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
            SelectedAESKeyLabel.Text = $"🔍 Geselecteerde sleutel: {selectedAESKeyName}";
            MessageBox.Show($"AES sleutel geselecteerd: {selectedAESKeyName}", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
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
                SelectedEncryptFileLabel.Text = $"📝 Geselecteerd bestand: {Path.GetFileName(selectedFileToEncrypt)}";

                // Automatisch een bestandsnaam voorstellen voor het output bestand
                string suggestedName = Path.GetFileNameWithoutExtension(selectedFileToEncrypt);
                EncryptOutputFilename.Text = $"{suggestedName}.txt";

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

                if (string.IsNullOrWhiteSpace(EncryptOutputFilename.Text))
                {
                    MessageBox.Show("Geef een naam op voor het output bestand!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
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

                // De pad voor het output bestand bepalen
                string outputFileName = EncryptOutputFilename.Text;
                if (!outputFileName.EndsWith(".txt"))
                {
                    outputFileName += ".txt";
                }
                string encryptedFilePath = Path.Combine(ciphertextFolderPath, outputFileName);

                // Encryptie uitvoeren en als Base64 opslaan
                EncryptFileToBase64(selectedFileToEncrypt, encryptedFilePath, key, iv);

                MessageBox.Show($"Bestand succesvol geëncrypt!\nOpgeslagen als: {encryptedFilePath}", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);

                // Laad de ciphertext bestanden opnieuw
                LoadCiphertextFiles_Click(sender, e);
            }
            catch (CryptographicException cx)
            {
                MessageBox.Show($"Cryptografische fout: {cx.Message}\nMogelijk gebruik je de verkeerde sleutel.", "Cryptografische Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het encrypten: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void EncryptFileToBase64(string inputFilePath, string outputFilePath, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                // Lees het input bestand in
                byte[] fileBytes = File.ReadAllBytes(inputFilePath);

                // Voer encryptie uit
                byte[] encryptedBytes;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(fileBytes, 0, fileBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        encryptedBytes = memoryStream.ToArray();
                    }
                }

                // Converteer naar Base64 en sla op
                string base64String = Convert.ToBase64String(encryptedBytes);
                File.WriteAllText(outputFilePath, base64String);
            }
        }

        private void SelectFileToDecrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = "Selecteer een bestand om te decrypten",
                Filter = "Text Files (*.txt)|*.txt|Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*",
                InitialDirectory = ciphertextFolderPath
            };

            if (openFileDialog.ShowDialog() == true)
            {
                selectedFileToDecrypt = openFileDialog.FileName;
                SelectedDecryptFileLabel.Text = $"📝 Geselecteerd bestand: {Path.GetFileName(selectedFileToDecrypt)}";

                // Automatisch een bestandsnaam voorstellen voor het output bestand
                string suggestedName = Path.GetFileNameWithoutExtension(selectedFileToDecrypt);
                DecryptOutputFilename.Text = $"{suggestedName}_decrypted.png";

                MessageBox.Show($"Geselecteerd bestand: {selectedFileToDecrypt}", "Bestand Gekozen", MessageBoxButton.OK, MessageBoxImage.Information);
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

                if (string.IsNullOrWhiteSpace(DecryptOutputFilename.Text))
                {
                    MessageBox.Show("Geef een naam op voor het output bestand!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
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

                // De pad voor het output bestand bepalen
                string outputFileName = DecryptOutputFilename.Text;
                string decryptedFilePath = Path.Combine(plaintextFolderPath, outputFileName);

                // Controleer of het een .enc bestand is (binair) of .txt bestand (Base64)
                if (Path.GetExtension(selectedFileToDecrypt).ToLower() == ".enc")
                {
                    // Binair bestand decryptie
                    DecryptFilesBinary(selectedFileToDecrypt, decryptedFilePath, key, iv);
                }
                else
                {
                    // Base64 string decryptie
                    DecryptBase64ToFile(selectedFileToDecrypt, decryptedFilePath, key, iv);
                }

                MessageBox.Show($"Bestand succesvol gedecrypt!\nOpgeslagen als: {decryptedFilePath}", "Succes", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (CryptographicException cx)
            {
                MessageBox.Show($"Cryptografische fout: {cx.Message}\nMogelijk gebruik je de verkeerde sleutel.", "Cryptografische Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (FormatException fx)
            {
                MessageBox.Show($"Formaat fout: {fx.Message}\nHet geselecteerde bestand is mogelijk geen geldig Base64 gecodeerd bestand.", "Formaat Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het decrypten: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DecryptFilesBinary(string inputFilePath, string outputFilePath, byte[] key, byte[] iv)
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

        private void DecryptBase64ToFile(string inputFilePath, string outputFilePath, byte[] key, byte[] iv)
        {
            // Lees de Base64 string
            string base64Content = File.ReadAllText(inputFilePath);

            // Converteer naar byte array
            byte[] encryptedBytes;
            try
            {
                encryptedBytes = Convert.FromBase64String(base64Content);
            }
            catch (FormatException)
            {
                throw new FormatException("De inhoud van het bestand is geen geldige Base64 string.");
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                // Decryptie uitvoeren
                using (MemoryStream memoryStream = new MemoryStream(encryptedBytes))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream outputStream = new FileStream(outputFilePath, FileMode.Create))
                {
                    cryptoStream.CopyTo(outputStream);
                }
            }
        }

        private void LoadCiphertextFiles_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CiphertextListBox.Items.Clear();

                if (string.IsNullOrEmpty(ciphertextFolderPath) || !Directory.Exists(ciphertextFolderPath))
                {
                    MessageBox.Show("Stel eerst een standaard ciphertext map in!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string[] files = Directory.GetFiles(ciphertextFolderPath, "*.txt");
                string[] encFiles = Directory.GetFiles(ciphertextFolderPath, "*.enc");

                // Combineer beide arrays
                string[] allFiles = new string[files.Length + encFiles.Length];
                files.CopyTo(allFiles, 0);
                encFiles.CopyTo(allFiles, files.Length);

                if (allFiles.Length == 0)
                {
                    MessageBox.Show("Geen ciphertext bestanden gevonden!", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                foreach (string file in allFiles)
                {
                    CiphertextListBox.Items.Add(Path.GetFileName(file));
                }

                MessageBox.Show($"Aantal gevonden ciphertext bestanden: {CiphertextListBox.Items.Count}", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij het laden van ciphertext bestanden: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SelectCiphertextFile_Click(object sender, RoutedEventArgs e)
        {
            if (CiphertextListBox.SelectedItem == null)
            {
                MessageBox.Show("Selecteer een ciphertext bestand uit de lijst!", "Fout", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string selectedFileName = CiphertextListBox.SelectedItem.ToString();
            selectedFileToDecrypt = Path.Combine(ciphertextFolderPath, selectedFileName);
            SelectedDecryptFileLabel.Text = $"📝 Geselecteerd bestand: {selectedFileName}";

            // Automatisch een bestandsnaam voorstellen voor het output bestand
            string suggestedName = Path.GetFileNameWithoutExtension(selectedFileName);
            DecryptOutputFilename.Text = $"{suggestedName}_decrypted.png";

            MessageBox.Show($"Ciphertext bestand geselecteerd: {selectedFileName}", "Bestand Gekozen", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}