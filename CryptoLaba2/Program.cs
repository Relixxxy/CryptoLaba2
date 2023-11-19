using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

// Encryption Key (256 bit)
byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
var engine = new Gost28147Engine();
var cfbBlockCipher = new CfbBlockCipher(engine, 64);
var cbcBlockCipher = new CbcBlockCipher(engine);

var plainText = "Hello, GOST 28147:2009!";

EncryptDecrypt("ECB", plainText, engine);
EncryptDecrypt("CFB", plainText, cfbBlockCipher);
EncryptDecrypt("CBC", plainText, cbcBlockCipher);

void EncryptDecrypt(string mode, string plainText, IBlockCipher blockCipher)
{
    Console.WriteLine($"===============   {mode} mode start  ===============");
    Console.WriteLine($"Plain text: {plainText}");

    var encryptedText = EncryptByGost28147(plainText, blockCipher);
    Console.WriteLine($"Encrypted text: {encryptedText}");

    var decryptedText = DecryptByGost28147(encryptedText, blockCipher);
    Console.WriteLine($"Decrypted text: {decryptedText}");
    Console.WriteLine($"===============    {mode} mode end    ===============\n");
}

string EncryptByGost28147(string plainText, IBlockCipher blockCipher)
{
    byte[] input = Encoding.UTF8.GetBytes(plainText);

    var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

    cipher.Init(true, new ParametersWithSBox(new KeyParameter(key), Gost28147Engine.GetSBox("E-A")));

    byte[] cipherText = new byte[cipher.GetOutputSize(input.Length)];
    int len = cipher.ProcessBytes(input, 0, input.Length, cipherText, 0);
    cipher.DoFinal(cipherText, len);

    var result = Convert.ToBase64String(cipherText);

    return result;
}

string DecryptByGost28147(string encryptedText, IBlockCipher blockCipher)
{
    byte[] cipherText = Convert.FromBase64String(encryptedText);

    var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

    cipher.Init(false, new ParametersWithSBox(new KeyParameter(key), Gost28147Engine.GetSBox("E-A")));

    byte[] decryptedText = new byte[cipher.GetOutputSize(cipherText.Length)];
    int len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, decryptedText, 0);
    cipher.DoFinal(decryptedText, len);

    var result = Encoding.UTF8.GetString(decryptedText);

    return result;
}