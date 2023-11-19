using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

// Ключ для шифрування (256 біт)
byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

var plainText = "Hello, GOST 28147:2009!";
var encryptedText = EncryptByGost28147(plainText);
Console.WriteLine("Encrypted text: " + encryptedText);

var decryptedText = DecryptByGost28147(encryptedText);
Console.WriteLine("Decrypted text: " + decryptedText);

string EncryptByGost28147(string plainText)
{
    byte[] input = Encoding.UTF8.GetBytes(plainText);
    // Create GOST 28147:2009 cipher with CFB mode and PKCS7 padding
    BufferedBlockCipher cipher = new BufferedBlockCipher(new CfbBlockCipher(new Gost28147Engine(), 8));

    // Initialize for encryption with key
    cipher.Init(true, new ParametersWithSBox(new KeyParameter(key), Gost28147Engine.GetSBox("E-A")));

    // Encrypt the data
    byte[] cipherText = new byte[cipher.GetOutputSize(input.Length)];
    int len = cipher.ProcessBytes(input, 0, input.Length, cipherText, 0);
    cipher.DoFinal(cipherText, len);

    var result = Convert.ToBase64String(cipherText);

    return result;
}

string DecryptByGost28147(string encryptedText)
{
    byte[] cipherText = Convert.FromBase64String(encryptedText);

    // Create GOST 28147:2009 cipher with CFB mode and PKCS7 padding
    BufferedBlockCipher cipher = new BufferedBlockCipher(new CfbBlockCipher(new Gost28147Engine(), 8));

    // Initialize for decryption with key
    cipher.Init(false, new ParametersWithSBox(new KeyParameter(key), Gost28147Engine.GetSBox("E-A")));

    // Decrypt the data
    byte[] decryptedText = new byte[cipher.GetOutputSize(cipherText.Length)];
    int len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, decryptedText, 0);
    cipher.DoFinal(decryptedText, len);

    var result = Encoding.UTF8.GetString(decryptedText);

    return result;
}