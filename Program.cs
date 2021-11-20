//@author: Mateusz779
using Mono.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace encryption_console
{
    class Program
    {
        public static List<string> passs=new List<string>();
        public static int leng_key = 128;
        public static int mode=-1;
        static void Main(string[] args)
        {
            bool show_help = false;
            string source = "";
            string dest = "";

            var p = new OptionSet() {
    { "s|source=", "Location source file",
       (string v) => source=v },

     { "d|dest=", "Destination of file",
       v => dest=v },
    { "m|mode=",
       "0 to encrypt 1 to decrypt" +
          "\nthis must be an integer.",
        (int v) => mode = v },
    { "p|pass=", "Password",
       v => passs.Add(v) },

    { "h|help",  "show this message and exit",
       v => show_help = v != null },
};

            List<string> extra;
            try
            {
                extra = p.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("greet: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try `greet --help' for more information.");
                return;
            }
            if (show_help)
            {
                for (int i = 0; i < p.Count; i++)
                    Console.WriteLine(p[i].Prototype+ "    "+ p[i].Description);
                return;
            }
                

            while (string.IsNullOrWhiteSpace(source))
            {
                Console.WriteLine("Location source file:");
                source = Console.ReadLine();
            }

            while (mode == -1)
            {
                Console.WriteLine("0 to encrypt 1 to decrypt:");
                int.TryParse(Console.ReadLine(), out mode);
            }
            while (passs.Count == 0)
            {
                string temp = "a";
                if (mode == 1)
                {
                    Console.WriteLine("Password:");
                    temp = null;
                    temp = Console.ReadLine();
                    if (!string.IsNullOrWhiteSpace(temp))
                        passs.Add(temp);
                    break;
                }
                else
                {
                    while (!string.IsNullOrWhiteSpace(temp))
                    {
                        Console.WriteLine("Password:");
                        temp = null;
                        temp = Console.ReadLine();
                        if (!string.IsNullOrWhiteSpace(temp))
                            passs.Add(temp);
                    }
                }
            }

            for (int i = 0; i < passs.Count; i++)
                passs[i] = passs[i];

            if (File.Exists(source))
            {
                if (mode == 0)
                    AES_Encrypt(source, dest);
                else
                    AES_Decrypt(source, passs[0], dest);
            }
            else
                Console.WriteLine($"File: {source} not found!");
        }

        private static Random random = new Random();
        public static string RandomString(int length)
        {//random string generator
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnoprstuwyz";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        public static RijndaelManaged setupAES(byte[] passwordBytes, byte[] salt, RijndaelManaged AES)
        {
            AES = new RijndaelManaged();
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000, HashAlgorithmName.SHA512);
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.None;
            AES.Mode = CipherMode.CBC;
            return AES;
        }

        static  string EncryptStringToBytes(string plainText, byte[] passwordBytes, byte[] salt)
        {
            string encrypted;
            RijndaelManaged AES = new RijndaelManaged();
            AES = setupAES(passwordBytes, salt, AES);
            //setup AES 

            ICryptoTransform encryptor = AES.CreateEncryptor(AES.Key, AES.IV); //create encryptor

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    byte[] temp = msEncrypt.ToArray();
                    encrypted = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            return encrypted;
        }

        static string DecryptStringFromBytes(byte[] toDec, byte[] passwordBytes, byte[] salt)
        {
            string plaintext = null;

            RijndaelManaged AES = new RijndaelManaged();
            AES = setupAES(passwordBytes, salt, AES);
            //setup AES 

            ICryptoTransform decryptor = AES.CreateDecryptor(AES.Key, AES.IV);

            using (MemoryStream msDecrypt = new MemoryStream(toDec))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }

        public static byte[] SaveHead(byte[] salt, List<string> pass, string main)
        {
            string text = null;
            for (int i = 0; i < pass.Count; i++)
            {
                text = text + EncryptStringToBytes(main, Encoding.ASCII.GetBytes(pass[i]), salt) + "|";
            }
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(Encoding.ASCII.GetBytes(pass.Count.ToString() + "|" + Encoding.ASCII.GetString(salt) + "|" + text)) + "\n");
        }
        public static string[] ReadHead(string str, string passwd)
        {
            string[] a = str.Split('|');
            string[] b = new string[2];
            b[0] = a[1];


            for (int i = 0; i < int.Parse(a[0]); i++)
            {
                try
                {
                    string temp = DecryptStringFromBytes(Convert.FromBase64String(a[i + 2]), Encoding.ASCII.GetBytes(passwd), Encoding.ASCII.GetBytes(a[1]));
                    if (temp.Length == leng_key)
                        b[1] = temp;

                }
                catch { }
            }

            return b;
        }

        private static void AES_Encrypt(string inputFile, string output = null)
        {
            string passwd = RandomString(leng_key);
            byte[] salt = Encoding.ASCII.GetBytes(RandomString(32));

            FileStream fsCrypt;
            if (output==null||string.IsNullOrWhiteSpace(output))
                fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create);
            else
                fsCrypt = new FileStream(output, FileMode.Create);

            byte[] passwordBytes = System.Text.Encoding.ASCII.GetBytes(passwd);

            RijndaelManaged AES = new RijndaelManaged();
            AES = setupAES(passwordBytes, salt, AES);
            AES.Padding = PaddingMode.PKCS7;

            byte[] to_save = SaveHead(salt, passs, passwd);
            fsCrypt.Write(to_save, 0, to_save.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }

                //close up
                fsIn.Close();

            }
            catch
            {
                //Debug.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
                Console.WriteLine("File has encrypted!");
            }
        }

        private static void AES_Decrypt(string inputFile, string password, string output=null)
        {
            byte[] temp = new byte[1048576];
            int len = 0;
            byte[] salt = new byte[32];
            byte[] passwordBytes = new byte[leng_key];

            try
            {
                using (var stream1 = new StreamReader(new FileStream(inputFile, FileMode.Open)))
                {
                    string from_stream = stream1.ReadLine();
                    temp = Convert.FromBase64String(from_stream);
                    len = from_stream.Length;
                    stream1.Close();
                }

                string[] tempp = ReadHead(Encoding.ASCII.GetString(temp), password);
                salt = Encoding.ASCII.GetBytes(tempp[0]);
                if (tempp[1] != null)
                    passwordBytes = System.Text.Encoding.ASCII.GetBytes(tempp[1]);
                else
                {
                    Console.WriteLine("Incorrect password!");
                    passwordBytes = null;
                }

            }
            catch
            {
                Console.WriteLine("Selected corrupted or invaild file!");
            }
            if (passwordBytes != null && passwordBytes.Length != 0)
            {
                FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);

                RijndaelManaged AES = new RijndaelManaged();
                AES = setupAES(passwordBytes, salt, AES);
                AES.Padding = PaddingMode.PKCS7;

                fsCrypt.Position = len + 1;
                fsCrypt.Seek(0, SeekOrigin.Current);

                CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);
                FileStream fsOut;
                if (output == null || string.IsNullOrWhiteSpace(output))
                    output = inputFile;
                if (output.IndexOf(".aes") != -1)
                {
                    output = output.Substring(0, output.IndexOf(".aes"));
                    fsOut = new FileStream(output, FileMode.Create);
                }

                else
                {
                    fsOut = new FileStream(output + ".decrypted", FileMode.Create);
                }

                int read;
                byte[] buffer = new byte[1048576];

                try
                {
                    while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        fsOut.Write(buffer, 0, read);
                    }
                }
                catch //(System.Security.Cryptography.CryptographicException ex_CryptographicException)
                {
                    //Debug.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
                    fsOut.Close();
                    //File.Delete(output);
                }
                try
                {
                    cs.Close();
                }
                catch
                {
                    //Debug.WriteLine("Error by closing CryptoStream: " + ex.Message);
                }
                finally
                {
                    fsOut.Close();
                    fsCrypt.Close();
                    Console.WriteLine("File has decrypted!");
                }
            }
        }
    }
}
