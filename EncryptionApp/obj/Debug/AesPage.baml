   M S B A M L   `   `   `  ����  EncryptionApp    EncryptionApp.AesPage   5      R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5      R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5        N� Title$   AES Encryptie en Decryptie��5      .��5      �� $
��Auto=�6   .��5   
   �� $��10q�6   .+�5	      �� $/��)📁 Standaardfolder Ciphertext instellen��6   $��16(�6G   $
��Bold"�6U   
�������6g   �� 5
       �� Orientation$ 
Horizontal=�6   .+�5      �� -   5        $!��📂 Kies Ciphertext-folder��5   ;   $	��200��6_   $��35��6k   ���#3498DB
�������$��	0,5,10,10q�6�   �� 5      -   5        $ ��📂 Kies Plaintext-folder��5   :   $	��200��6]   $��35��6i   ���#3498DB
�������$��0,5,0,10q�6�   5      �� 5      -   5        $��CiphertextFolderLabel��5      $)��#📁 Ciphertext map: Niet ingesteld��65   $��12(�6^   $��0,0,0,5q�6l   
�������6}   �� 5      -   5        $��PlaintextFolderLabel��5      $(��"📁 Plaintext map: Niet ingesteld��64   $��12(�6\   $��0,0,0,10q�6j   
�������6|   �� 5      $��Beschikbare AES sleutels��6   $��16(�68   $
��Bold"�6F   $��0,10,0,0q�6X   
�������6j   �� 5      $ 
Horizontal=�6   .+�5      �� -   5        $��LoadAESKeys��5      $��🔄 Laad AES Sleutels��6,   $	��200��6K   $��35��6W   ���#1ABC9C
�������6�   5      �� 5      -   5        $��AESKeyListBox��5      $	��550��6+   $	��120��67   
�������
���   �$��0,10,0,0q�6j   �� 5      -   5        $��SelectAESKey��5      $��✅ Selecteer AES Sleutel��6)   $	��200��6K   $��35��6W   ���#2ECC71$
��Left=�6x   
�������$��0,5,0,0q�6�   6�   �� 5      -   5        $��SelectedAESKeyLabel��5      $��14(�63   $
��Bold"�6A   $&�� 🔍 Geselecteerde sleutel: Geen��6S   $��0,10,0,0q�6y   
�������6�   �� 5      $'��!Selecteer bestand om te encrypten��6   $��16(�6A   $
��Bold"�6O   $��0,20,0,0q�6a   
�������6s   �� 5       $ 
Horizontal=�6   .+�5!      �� -	   5        $��SelectFileToEncrypt��5!      $��📂 Kies bestand��64   $	��200��6N   $��35��6Z   ���#F1C40F
�������6�   �� 5"      -
   5        $��EncryptFile��5"      $��🔐 Encrypt Bestand��6,   $	��200��6I   $��35��6U   ���#16A085
�������$��10,0,0,0q�6�   6�   5#      �� 5$      -   5        $��SelectedEncryptFileLabel��5$      $%��📝 Geselecteerd bestand: Geen��68   $��12(�6]   $��0,5,0,0q�6k   
�������6|   �� 5%      $��0,5,0,0q�6   
�������.��68   '%U kan hier de bestandsnaam aanpassen:6_   �� 5&      -   5        $��EncryptOutputFilename��5&      $	��400��63   $
��Left=�6?   $��30��6Z   $��0,5,0,20q�6f   $-��'Voer bestandsnaam in voor ciphertext...��6x   �� 5)      $'��!Selecteer bestand om te decrypten��6   $��16(�6A   $
��Bold"�6O   $��0,10,0,0q�6a   
�������6s   �� 5*      $ 
Horizontal=�6   .+�5+      �� -   5        $��SelectFileToDecrypt��5+      $��📂 Kies bestand��64   $	��200��6N   $��35��6Z   ���#F39C12
�������6�   �� 5,      -   5        $��DecryptFile��5,      $��🔑 Decrypt Bestand��6,   $	��200��6I   $��35��6U   ���#E74C3C
�������$��10,0,0,0q�6�   6�   5-      �� 5.      -   5        $��SelectedDecryptFileLabel��5.      $%��📝 Geselecteerd bestand: Geen��68   $��12(�6]   $��0,5,0,0q�6k   
�������6|   �� 50      $��0,10,0,0q�6   
�������.��69   '%U kan hier de bestandsnaam aanpassen:6`   �� 51      -   5        $��DecryptOutputFilename��51      $	��400��63   $
��left=�6?   $��30��6Z   $��0,0,0,10q�6f   $��Geen bestand geselecteerd��6y   �� 54      $+��%📜 Beschikbare ciphertext-bestanden��6   $��16(�6C   $
��Bold"�6Q   $��0,10,0,0q�6c   
�������6u   �� 55      -   5        $��CiphertextListBox��55      $	��550��6/   $	��120��6;   
�������
���   �$��0,10,0,0q�6n   56      57      58      