using ECDHAES256;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HUSH_RATCHET_DEMO
{
    public partial class WhisperRatchet : Form
    {
        public Alice alice;
        public Bob bob;
        public WhisperRatchet()
        {
            InitializeComponent();
        }

        private void initBtn_Click(object sender, EventArgs e)
        {
            alice = new Alice();
            bob = new Bob();
            bob.ratchet = new Hush.Ratchet();
            alice.ratchet = new Hush.Ratchet();
            bob.cng = new CNG();
            alice.cng = new CNG();
            alice.ratchet.dh = new DH();
            bob.ratchet.dh = new DH();
            alice.cng = alice.ratchet.dh.a(new CNG());


            //exchange
            bob.cng.bpublicKey = alice.cng.publicKey;

            bob.cng = bob.ratchet.dh.b(bob.cng); //MAKE KEY FROM ALICE

            alice.cng.bpublicKey = bob.cng.publicKey;

            alice.cng = alice.ratchet.dh.a(alice.cng); //MAKE KEY FROM BOB

            
            alice.whisperer = new Hush.Whisperer();
            bob.whisperer = new Hush.Whisperer();
            alice.whisper = new Hush.Whisper();
            alice.whisper.cng = alice.cng;
            bob.whisper = new Hush.Whisper();
            bob.whisper.cng = bob.cng;
            update();


        }

        private void ain_Click(object sender, EventArgs e)
        {
            ain.Text = "";
        }

        private void bin_Click(object sender, EventArgs e)
        {
            bin.Text = "";
        }

        private void Alicebtn_Click(object sender, EventArgs e)
        {
            //Alice prepare
            alice.whisper.name = "alice";
            bob.whisper.name = "bob";
            alice.whisper.cng.plaintextBytes = Encoding.ASCII.GetBytes(ain.Text);
            alice.whisper = alice.whisperer.whisper(alice.whisper);
            //Alice Send
            update();
        }

        private void bobBtn_Click(object sender, EventArgs e)
        {
            alice.whisper.name = "alice";
            bob.whisper.name = "bob";
            bob.whisper.cng.plaintextBytes = Encoding.ASCII.GetBytes(bin.Text);
            bob.whisper = bob.whisperer.whisper(bob.whisper);
            update();
            
        }

        private void asend_Click(object sender, EventArgs e)
        {
            alice.whisper.name = "alice";
            bob.whisper.name = "bob";
            alice.whisper.cng.plaintextBytes = Encoding.ASCII.GetBytes(ain.Text);
            alice.whisper = alice.whisperer.whisper(alice.whisper);
            bob.whisper.bytes = alice.whisper.bytes; //TRANSFER WHISPER
            //Bob Recieved

            //Bob parses
            bob.whisper = bob.whisperer.listen(bob.whisper);
            bout.AppendText(Encoding.ASCII.GetString(bob.whisper.bytes));
            //bout.AppendText("\r\n");
            update();
        }
        private void update()
        {

            akey.Text = Convert.ToBase64String(bob.whisper.cng.key);
            bkey.Text = Convert.ToBase64String(alice.whisper.cng.key);
            bpk.Text = Convert.ToBase64String(bob.whisper.cng.publicKey);
            apk.Text = Convert.ToBase64String(alice.whisper.cng.publicKey);
            if (bob.whisper.publicKey!= null)
                bobpk.Text = Convert.ToBase64String(bob.whisper.publicKey);
            if (alice.whisper.publicKey != null)
                alicepk.Text= Convert.ToBase64String(alice.whisper.publicKey);

            if (bob.whisper.ratchet.cng.key != null)
            {
             
                bratchet.Text = Convert.ToBase64String(bob.whisper.ratchet.cng.key);
            }
            if (alice.whisper.ratchet.cng.key != null)
            {
                
                aratchet.Text = Convert.ToBase64String(alice.whisper.ratchet.cng.key);
            }
        }
        private void bsend_Click(object sender, EventArgs e)
        {
            alice.whisper.name = "alice";
            bob.whisper.name = "bob";
            bob.whisper.cng.plaintextBytes = Encoding.ASCII.GetBytes(bin.Text);
            bob.whisper = bob.whisperer.whisper(bob.whisper);
            alice.whisper.bytes = bob.whisper.bytes; //TRANSFER WHISPER
            //alice Recieved

            //alice parses
            alice.whisper = alice.whisperer.listen(alice.whisper);
            aout.AppendText(Encoding.ASCII.GetString(alice.whisper.bytes));
            //aout.AppendText("\r\n");
            update();
        }
    }
    public struct Alice
    {
        public CNG cng;
        public Hush.Ratchet ratchet;
        public Hush.Whisperer whisperer;
        public Hush.Whisper whisper;
    }
    public struct Bob
    {
        public CNG cng;
        public Hush.Ratchet ratchet;
        public Hush.Whisperer whisperer;
        public Hush.Whisper whisper;
    }
}
namespace Hush
{
    using Compression;
    using ECDHAES256;
    using System.IO;
    public struct Whisper
    {

        public void Clean(bool cleanBytes = false)
        {
            messageSize = new byte[4];
            compressionSize = new byte[4];
            if (cleanBytes == true)
            { bytes = null; }
            obj = null;
        }
        public bool ratchetIsPrimmed;
        public AES aes;
        public DH dh;
        public CNG cng;
        public Ratchet ratchet;
        public Compression compression;
        public string name;
        public object obj;
        public byte[] messageSize;
        public byte[] compressionSize;
        public byte[] publicKey;
        public byte[] bytes;
    }
    public struct Ratchet
    {
        public CNG cng;
        public DH dh;
        public bool aliceReady;
        public bool bobReady;
    }
    public class Whisperer
    {

        /*A Whisper is an AES256 encryption packet protocol defined as *******************************************
        *   whisper() encapsulates compresses and encrypts
        *   listen() decrypts decompresses and decapsulates
        *   4 byte Int32 for compressed payload size
        *   4 byte Int32 for original uncompressed size of payload
        *   140 byte for public key
        *   rest is Payload
        *   
        *   provide 256 bit key in Whisp.cng.key USES: ECDHAES256
        *
        *   returned is aes.cng.encryptedBytes appended to the aes.cng.iv
        *
        ***************************************************************************************/
        public Whisper whisp;

        /// <summary>Forward Secrecy: Whisper Softly [4 byte Int32 for compressed payload size in bytes]+[4 byte Int32 for original payload size in bytes]+[Payload]</summary>
        public Whisperer()
        {
            whisp = new Whisper();
            whisp.dh = new DH();
            whisp.aes = new AES();
            whisp.compression = new Compression();
            whisp.cng = new CNG();
            whisp.ratchet = new Ratchet();
            whisp.ratchet.dh = new DH();
        }
        /// <summary>Speak in a Whisper..Supply whisper.cng.key and whsiper.cng.plaintextBytes</summary>
        /// <param name="whisper"> Supply whisper.cng.key and whsiper.cng.plaintextBytes</param>
        public Whisper whisper(Whisper whisper)
        {
            try
            {
                //whisp = readyRatchet(whisp); //public key ready for next dh exchange
                whisper = ratchet(whisper);
                whisper.publicKey = whisper.ratchet.cng.publicKey;
                if (whisper.cng.plaintextBytes == null && whisper.bytes != null)
                {
                    whisper.cng.plaintextBytes = whisper.bytes;
                }
                //Label Compression Original Size
                whisper.compressionSize = BitConverter.GetBytes(whisper.cng.plaintextBytes.Length);
                //Compress
                whisper.compression = new Compression();
                byte[] compressedBytes = whisper.compression.CompressBytesToBytes(whisper.cng.plaintextBytes);
                //label Compressed message size             
                whisper.messageSize = BitConverter.GetBytes(compressedBytes.Length); //PLUS 2 for HEADER
                //MAKE READY PACKET *** ADD PUBLIC KEY ***
                IEnumerable<byte> result = whisper.messageSize.Concat(whisper.compressionSize).Concat(whisper.publicKey).Concat(compressedBytes);
                whisper.cng.plaintextBytes = result.ToArray(); //header is first 8+140 bytes
                //Encrypt PACKET
                whisper.aes = new AES();
                whisper.cng = whisper.aes.encrypt(whisper.cng);
                //Return Whisp, 
                IEnumerable<byte> result2 = whisper.cng.iv.Concat(whisper.cng.encryptedBytes);
                whisper.bytes = result2.ToArray();
                whisper.ratchet.aliceReady = true;
                if (whisper.ratchet.aliceReady && whisper.ratchet.bobReady )
                { whisper = ratchet(whisper); }
                whisper.Clean();

                return whisper;
            }
            catch (Exception e)
            {
                whisper.obj = e;
                return whisper;
            }
        } //you supply whisp.cng
        /// <summary>Listen to a Whisper..Supply whisper.cng.key and whisper.cng.encryptedBytes</summary>
        /// <param name="whisper"> Supply whisper.cng.key and whisper.cng.encryptedBytes</param>
        public Whisper listen(Whisper whisper)
        {
            /*supply whisper.cng.key and whisper.bytes
            *   Whisper whisper = new Whisper();
            *   Whisp whisp = new Whisp();
            *   whisp.cng.key = yourKey; //256 byte key for AES256
            *   whisp.bytes = yourRecievedWhispBytes;
            *   whisp = whisper.listen(whisp);
            *   parse(whisp.bytes);
            */
            try
            {
                using (MemoryStream encrypted = new MemoryStream(whisper.bytes))
                {


                    //Decrypt whisper
                    whisper.cng.iv = new byte[16];
                    encrypted.Read(whisper.cng.iv, 0, 16);

                    whisper.cng.encryptedBytes = new byte[Convert.ToInt32(encrypted.Length) - 16];
                    encrypted.Read(whisper.cng.encryptedBytes, 0, whisper.cng.encryptedBytes.Length);
                    whisper.aes = new AES();
                    whisper.cng = whisper.aes.decrypt(whisper.cng); //USE CURRENT KEY
                    //whisper.Clean(true);
                    using (MemoryStream stream = new MemoryStream(whisper.cng.plaintextBytes))
                    {
                        whisper.messageSize = new byte[4];
                        whisper.compressionSize = new byte[4];
                        stream.Read(whisper.messageSize, 0, 4);
                        stream.Read(whisper.compressionSize, 0, 4);
                        whisper.publicKey = new byte[140]; //GET RATCHET PUBLIC KEY
                        stream.Read(whisper.publicKey, 0, whisper.publicKey.Length);
                        byte[] compressed = new byte[BitConverter.ToInt32(whisper.messageSize, 0)];
                        stream.Read(compressed, 0, compressed.Length);
                        whisper.bytes = new byte[BitConverter.ToInt32(whisper.compressionSize, 0)];
                        //Decompress 
                        whisper.compression = new Compression();
                        whisper.bytes = whisper.compression.DeCompressBytesToBytes(compressed, BitConverter.ToInt32(whisper.compressionSize, 0));
                        whisper.ratchet.bobReady = true; //recieved public key from alice
                        whisper = ratchet(whisper); //RATCHET KEY MADE whisper.cng is replaced
                        
                        //returnable.Clean();
                        return whisper;
                    }

                }
            }
            catch (Exception e)
            {
                whisper.obj = e;
                return whisper;
            }
        }
        private Whisper primeRatchet(Whisper whisp)
        {
            try
            {
                if (whisp.ratchetIsPrimmed == false)
                {
                    whisp.ratchet.dh = new DH();
                    if ( whisp.publicKey!=null)//whisp.ratchet.cng.key== null &&
                    {
                        whisp.ratchet.cng = new CNG();
                        whisp.ratchet.cng.bpublicKey = whisp.publicKey;
                        whisp.ratchet.cng = whisp.ratchet.dh.b(whisp.ratchet.cng); //KEY MADE BUT NOT READY TO USE unless you call bobReady=true
                    }
                    else { //is null
                        whisp.ratchet.cng = whisp.ratchet.dh.a(new CNG()); //ratchet houses alice now
                    }
                     //PROBLEM!!!! moved to whisper
                    //whisp.ratchet.aliceReady = true;
                    whisp.ratchetIsPrimmed = true;
                    return whisp;
                }
                
                return whisp;
            }
            catch (Exception e)
            {
                whisp.obj = e;
                return whisp;
            }
        }
        private Whisper ratchet(Whisper whisp)
        {
            try
            {
                //whisp.ratchet.cng.alice == null && whisp.ratchet.cng.publicKey==null
                if (whisp.ratchetIsPrimmed==false) //IF this is the first ratchet
                {
                    whisp = primeRatchet(whisp); //aliceReady is still false until first send
                }
                if (whisp.ratchet.aliceReady == true && whisp.ratchet.bobReady==true) //both sides ready to ratchet
                {//alice must be present and bpublic key must be present
                    //PROBLEM BOB JUST SEND PK
                    if (whisp.ratchet.cng.key == null)
                    {
                        whisp.ratchet.cng.bpublicKey = whisp.publicKey;                        
                        whisp.ratchet.cng = whisp.ratchet.dh.a(whisp.ratchet.cng); //makes key
                    }else if (whisp.ratchet.cng.key!=null)
                    {
                        //key was already made
                    }
                    //TRANSFER
                    whisp.cng = whisp.ratchet.cng; //MAY NEED CLEANING FIRST
                    //CLEAN
                    whisp.ratchet.dh = new DH();
                    //whisp.ratchet.cng = new CNG(); //new alice
                    whisp.ratchetIsPrimmed = false;
                    whisp.ratchet.aliceReady = false;
                    whisp.ratchet.bobReady = false;
                    whisp.publicKey = null;
                    //whisp.cng.clean();
                    
                    return whisp;
                }
                return whisp;
            }
            catch (Exception e)
            { whisp.obj = e; return whisp; }
        }
    }
}
namespace ECDHAES256
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    public struct CNG
    {
        public void clean()
        {
            alice = null;
            bob = null;
            iv = null;
            bpublicKey = null;
            encryptedBytes = null;
            plaintextBytes = null;
        }
        public CngKey cngkey;
        public ECDiffieHellmanCng alice;
        public ECDiffieHellmanCng bob;
        public Byte[] key;
        public Byte[] iv;
        public Byte[] publicKey;
        public Byte[] bpublicKey;
        public Byte[] encryptedBytes;
        public Byte[] plaintextBytes;
    }
    public class AES
    {
        public CNG cng { get; set; }
        public byte[] key { get; set; }
        public AES()
        {
            CNG c = new CNG();
            c.key = key = RijndaelManaged.Create().Key;
            cng = c;
        }
        public CNG encrypt(CNG c)
        {
            EncryptMessage(c.key, c.plaintextBytes, out c.encryptedBytes, out c.iv);
            c.plaintextBytes = null;
            return c;
        }
        private void EncryptMessage(Byte[] key, Byte[] plaintextMessage, out Byte[] encryptedMessage, out Byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                }

            }
        }
        public CNG decrypt(CNG c)
        {
            DecryptMessage(out c.plaintextBytes, c.encryptedBytes, c.iv, c.key);
            c.encryptedBytes = null;
            c.iv = null;
            return c;
        }
        private void DecryptMessage(out Byte[] plaintextBytes, Byte[] encryptedBytes, Byte[] iv, Byte[] bkey)
        {

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = bkey;
                aes.IV = iv;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                        cs.Close();
                        encryptedBytes = null;
                        plaintextBytes = plaintext.ToArray();
                    }
                }
            }
        }
    }
    public class DH
    {
        private static CNG cng;
        public DH()
        {
            cng = new CNG();
        }
        public CNG a(CNG c)
        {
            if (c.alice == null)
            {
                c.alice = new ECDiffieHellmanCng();

                c.alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                c.alice.HashAlgorithm = CngAlgorithm.Sha256;
                c.publicKey = c.alice.PublicKey.ToByteArray();
                c.encryptedBytes = null;
                c.iv = null;
                c.plaintextBytes = null;
                return c;

            }
            if (c.alice != null)
            {
                try
                {
                    c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                    c.key = c.alice.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                    c.iv = null;
                    //c.publicKey = null;
                    c.bpublicKey = null;
                    //c.bob = null;
                    c.encryptedBytes = null;
                    c.plaintextBytes = null;
                    //c.alice = null;
                    return c;
                }
                catch (Exception) { return c; }

            }
            
            c.iv = null;
            //c.publicKey = null;
            c.bpublicKey = null;
            //c.bob = null;
            c.encryptedBytes = null;
            c.plaintextBytes = null;
            //c.alice = null;
            return c;
        }
        public CNG b(CNG c)
        {
            if (c.bob == null)
            {
                c.bob = new ECDiffieHellmanCng();

                c.bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                c.bob.HashAlgorithm = CngAlgorithm.Sha256;
                c.publicKey = c.bob.PublicKey.ToByteArray();
                //c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                c.key = c.bob.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                c.iv = null;
                c.bpublicKey = null;
                //c.bob = null;
                c.encryptedBytes = null;
                c.plaintextBytes = null;
               // c.alice = null;
                return c;

            }
            if (c.bob != null)
            {

                c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                //c.bcngkey = c.cngkey;
                c.key = c.bob.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));

                
                c.encryptedBytes = null;
                c.iv = null;
                //c.publicKey = null;
                c.bpublicKey = null;
                //c.bob = null;
                c.plaintextBytes = null;
                //c.alice = null;
                return c;

            }
            c.encryptedBytes = null;
            c.iv = null;
            //c.publicKey = null;
            c.bpublicKey = null;
          //c.bob = null;
            c.encryptedBytes = null;
            c.plaintextBytes = null;
            //c.alice = null;
            return c;
        }
    }
}
namespace Compression
{
    using System;
    using System.Text;
    using System.IO;
    using System.IO.Compression;

    public class Compression
    {

        public byte[] getBytes { get; private set; }
        public Compression()
        { }
        public Compression(byte[] input)
        {
            getBytes = CompressBytesToBytes(input);
        }
        public Compression(byte[] bytes, long bufferSize)
        {
            getBytes = DeCompressBytesToBytes(bytes, bufferSize);
        }
        public byte[] CompressStringToBytes(string input)
        {
            using (MemoryStream resultStream = new MemoryStream())
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                         CompressionLevel.Optimal))
                {
                    byte[] inBuffer = Encoding.UTF8.GetBytes(input);
                    compressionStream.Write(inBuffer, 0, inBuffer.Length);
                }
                return resultStream.ToArray();
            }
        }
        public byte[] CompressBytesToBytes(byte[] inBuffer)
        {
            using (MemoryStream resultStream = new MemoryStream())
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                         CompressionLevel.Optimal))
                {
                    compressionStream.Write(inBuffer, 0, inBuffer.Length);
                }
                return resultStream.ToArray();
            }
        }

        public String DeCompressBytesToString(byte[] bytes, long OriginalSize)
        {
            using (MemoryStream resultStream = new MemoryStream(bytes))
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                        CompressionMode.Decompress))
                {
                    byte[] outBuffer = new byte[OriginalSize];   // need an estimate here
                    int length = compressionStream.Read(outBuffer, 0, outBuffer.Length);
                    return Encoding.UTF8.GetString(outBuffer, 0, length);
                }
            }
        }
        public byte[] DeCompressBytesToBytes(byte[] bytes, long OriginalSize)
        {
            using (MemoryStream resultStream = new MemoryStream(bytes))
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                        CompressionMode.Decompress))
                {
                    byte[] outBuffer = new byte[OriginalSize];   // need an estimate here
                    int length = compressionStream.Read(outBuffer, 0, outBuffer.Length);
                    return outBuffer;
                }
            }
        }
    }
}