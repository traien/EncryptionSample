using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

class EncryptionSample
{
    static void Main()
    {
        Console.WriteLine("Encryption Sample");

        EncryptionHelper helper = new EncryptionHelper();

        helper.AESEncryptFile("super-secret-file.txt", Encoding.UTF8.GetBytes("super-secret-password"), false);

        Console.Write("Encrypted File: " + "super-secret-file.txt.enc");
    }
}