using System;
using System.Collections.Generic;
using System.Linq;
namespace Whisper_Server_Package
{
    using System;
    using System.Net.Sockets;
    using System.ComponentModel;
    using System.Net;
    public partial struct QUERY
    {
        public DATA[] clients;
        public DATA[] masters;
        public bool[] cMIDs;
        public bool[] mMIDs;

    }
    public partial struct SERVER_DATA
    {

        public QUERY query;
        public object update;
        public DATA data;
        public ECDHAES256.AES crypto;
        public ECDHAES256.DH dh;
        public PACKET packet;
        public CNGPACKET cpac;
        public SERVER server;
        public ACCOUNT[] accounts_DB;
        public ACCOUNT[] connected_Accounts;
        public int MID;
        public int CID;
        public int AID;

    }
    public partial struct ACCOUNT
    {
        public String Name;
        public String Key;
        public String Id;
        public String Ip;
        public String[] Keys;
        public String[] IPs;
        public Object Tag;
        public String isMaster;
    }
    public partial struct PACKET
    {
        public String ip;
        public String arg;
        public String length;
        public String flag;
        public String data;
        public object tag;
        public Byte[] bytes;
    }
    public partial struct CNGPACKET
    {
        public byte[] iv;
        public byte[] enc;
        public object tag;
        public byte[] bytes;
    }
    public partial struct DATA
    {

        public void Clean()
        {
            try
            {
                packet = new PACKET();
                bytes = null;
                cng.iv = null;
                cng.plaintextBytes = null;
                cng.encryptedBytes = null;
            }
            catch (Exception)
            { }
        }
        public bool useCompression;
        public bool useWhisper;
        public WhisperProtocol.Whisperer whisperer;
        public WhisperProtocol.Whisp whisp;
        public Int32 RecieveBufferSize;
        public String lastSend;
        public String lastRecv;
        public Object controller;
        public Type controllerType;
        public Func<DATA, DATA> taskFunction;
        public Func<DATA, DATA> faultFunction;
        public ACCOUNT account;
        public BackgroundWorker worker;
        public PACKET packet;
        public CNGPACKET cpac;
        public String RHOST;
        public Int32 RPORT;
        public TcpClient client;
        public TcpListener server;
        public NetworkStream stream;
        public object tag;
        public Byte[] bytes;
        public ECDHAES256.CNG cng;
        public ECDHAES256.CNG ratchet;
        public bool useCng;
        public ECDHAES256.DH dh;
        public String MIP;
        public bool IsMaster;
        public bool IsReturned;
        public bool IsConnected;
        public int CID;
        public int MID;
    }
    public partial class SERVER
    {
        public DATA data { get; set; }
        public Func<DATA, DATA> faultfunction { get; set; }
        public SERVER()
        {
            data = new DATA();
        }
        private String addHEAD(int data, PACKET packet)
        {
            String[] HEADER = new String[6];
            HEADER[0] = "<START>";
            HEADER[1] = "<IP>" + packet.ip;
            HEADER[2] = "<ARG>" + packet.arg;
            HEADER[3] = "<LENGTH>" + packet.length;
            HEADER[4] = "<FLAG>" + packet.flag;
            HEADER[5] = "<DATA>";
            return HEADER[0] + HEADER[1] + HEADER[2] + HEADER[3] + HEADER[4] + HEADER[5];
        }
        private String addFOOT()
        {
            return "<END>";
        }
        private Byte[] buildRequest(PACKET packet)
        {
            //CAN ADD AES HERE TO ENCRPYT PACKET BEFORE RETURN
            if (packet.data == null)
            {
                String PACKET = addHEAD(0, packet) + addFOOT();
                return System.Text.Encoding.ASCII.GetBytes(PACKET);

            }
            else {
                String PACKET = addHEAD(packet.data.Length, packet) + packet.data + addFOOT();
                return System.Text.Encoding.ASCII.GetBytes(PACKET);

            }
        }
        public DATA makePacket(DATA d)
        {
            try
            {
                String dat = System.Text.Encoding.ASCII.GetString(d.packet.bytes, 0, d.packet.bytes.Length);
                d.bytes = d.packet.bytes;
                d.packet = new PACKET();
                if (dat.Contains("<SPLIT>"))
                {
                    dat = dat.Replace("<SPLIT>", "~");
                    String[] tmp = dat.Split('~');
                    d.cng.iv = Convert.FromBase64String(tmp[0]);
                    tmp = tmp[1].Split('\0');
                    d.cng.encryptedBytes = Convert.FromBase64String(tmp[0]);
                    tmp = null;

                    ECDHAES256.AES crypto = new ECDHAES256.AES();
                    crypto.cng = crypto.decrypt(d.cng); //TODO PROBLEM HERE
                    d.cng.plaintextBytes = crypto.cng.plaintextBytes;

                    dat = System.Text.Encoding.ASCII.GetString(d.cng.plaintextBytes, 0, d.cng.plaintextBytes.Length);
                    d.cng.plaintextBytes = null;
                    d.cng.encryptedBytes = null;
                    d.cng.iv = null;
                }
                if (dat.Contains("<ARG>") && dat.Contains("<LENGTH>") && dat.Contains("<FLAG>") && dat.Contains("<DATA>") && dat.Contains("<END>"))
                {
                    try
                    {
                        String[] valid = { "<ARG>", "<LENGTH>", "<FLAG>", "<DATA>", "<END>" };
                        dat = dat.Replace("<START>", "");
                        dat = dat.Replace("<IP>", "");
                        int i;
                        for (i = 0; i < valid.Length; ++i)
                        {
                            dat = dat.Replace(valid[i], "~");
                        }
                        String[] dd = dat.Split('~');
                        if (dd.Length > 1)
                        {
                            d.packet.ip = dd[0];
                            d.packet.arg = dd[1];
                            d.packet.length = dd[2];
                            d.packet.flag = dd[3];
                            d.packet.data = dd[4];
                        }
                        else {
                            d.packet.arg = "";
                            d.packet.ip = "";
                            d.packet.length = "-1";
                            d.packet.flag = "";
                            d.packet.data = "";
                        }
                        return d;
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("\nError in makePacket");
                        PACKET pack = new PACKET();
                        pack.arg = "";
                        pack.ip = "";
                        pack.length = "-1";
                        pack.flag = "";
                        pack.data = "";
                        d.packet = pack;
                    }
                }
            }
            catch (Exception)
            { d.packet = new PACKET(); d.packet.length = "-1"; }
            return d;
        }
        private byte[] trimByte(byte[] input)
        {
            if (input.Length > 1)
            {
                int byteCounter = input.Length - 1;
                while (input[byteCounter] == 0x00)
                {
                    byteCounter--;
                }
                byte[] rv = new byte[(byteCounter + 1)];
                for (int byteCounter1 = 0; byteCounter1 < (byteCounter + 1); byteCounter1++)
                {
                    rv[byteCounter1] = input[byteCounter1];
                }
                return rv;
            }
            else { return input; }
        }
        public DATA makeCngPacket(DATA d)
        {
            try
            {

                ECDHAES256.AES crypto = new ECDHAES256.AES();
                d.cng.encryptedBytes = trimByte(d.cng.encryptedBytes); //trim nulls
                crypto.cng = crypto.decrypt(d.cng); //TODO PROBLEM HERE
                d.cng.plaintextBytes = crypto.cng.plaintextBytes;
                string dat = System.Text.Encoding.ASCII.GetString(d.cng.plaintextBytes, 0, d.cng.plaintextBytes.Length);
                d.cng.plaintextBytes = null;
                d.cng.encryptedBytes = null;
                d.cng.iv = null;

                if (dat.Contains("<ARG>") && dat.Contains("<LENGTH>") && dat.Contains("<FLAG>") && dat.Contains("<DATA>") && dat.Contains("<END>"))
                {
                    try
                    {
                        String[] valid = { "<ARG>", "<LENGTH>", "<FLAG>", "<DATA>", "<END>" };
                        dat = dat.Replace("<START>", "");
                        dat = dat.Replace("<IP>", "");
                        int i;
                        for (i = 0; i < valid.Length; ++i)
                        {
                            dat = dat.Replace(valid[i], "~");
                        }
                        String[] dd = dat.Split('~');
                        if (dd.Length > 1)
                        {
                            d.packet.ip = dd[0];
                            d.packet.arg = dd[1];
                            d.packet.length = dd[2];
                            d.packet.flag = dd[3];
                            d.packet.data = dd[4];
                        }
                        else {
                            d.packet.arg = "";
                            d.packet.ip = "";
                            d.packet.length = "-1";
                            d.packet.flag = "";
                            d.packet.data = "";
                        }
                        return d;
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("\nError in makePacket");
                        PACKET pack = new PACKET();
                        pack.arg = "";
                        pack.ip = "";
                        pack.length = "-1";
                        pack.flag = "";
                        pack.data = "";
                        d.packet = pack;
                    }
                }
            }
            catch (Exception)
            { d.packet = new PACKET(); d.packet.length = "-1"; }
            return d;
        }
        public BackgroundWorker createRecvWorker()
        {
            //Program p = new Program(); //possible problem
            BackgroundWorker backgroundWorker1 = new BackgroundWorker();
            backgroundWorker1.WorkerSupportsCancellation = true;
            backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(worker_DoWork);
            backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(worker_RunWorkerCompleted);
            return backgroundWorker1;
        }
        public BackgroundWorker createWhisperWorker()
        {
            //Program p = new Program(); //possible problem
            BackgroundWorker backgroundWorker1 = new BackgroundWorker();
            backgroundWorker1.WorkerSupportsCancellation = true;
            backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(whisper_DoWork);
            backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(whisper_RunWorkerCompleted);
            return backgroundWorker1;
        }
        public DATA acceptClient(DATA d) //add whisperer
        {
            d.client = d.server.AcceptTcpClient();
            if (d.client.Connected)
            {
                if (d.useWhisper)
                {
                    d.whisperer = new WhisperProtocol.Whisperer();
                    d.whisp = new WhisperProtocol.Whisp();
                }
                d.stream = d.client.GetStream();
                return d;
            }
            return d;
        }
        public DATA StartServer(DATA d)
        {

            d.server = null;
            try
            {
                IPAddress localAddr = IPAddress.Any;
                d.server = new TcpListener(localAddr, d.RPORT);
                d.server.Start();
            }
            catch (Exception e)
            {
                d.tag = e;
            }
            return d;

        }
        public DATA keyExchangeAlice(DATA client_data)
        {

            client_data.dh = new ECDHAES256.DH();
            client_data.cng = new ECDHAES256.CNG();
            client_data.cng = client_data.dh.a(client_data.cng);
            client_data.packet = new PACKET();
            client_data.packet.flag = "INIT";
            client_data.packet.data = BASE64(client_data.cng.publicKey);
            client_data = Send(client_data);
            client_data.packet = new PACKET();
            client_data.packet.bytes = new Byte[4096];
            Int32 i = client_data.stream.Read(client_data.packet.bytes, 0, client_data.packet.bytes.Length);
            client_data = makePacket(client_data);
            if (!client_data.packet.flag.Equals("RET_INIT")) { }
            client_data.cng.bpublicKey = FROMBASE64(client_data.packet.data); //remote bob local alice meet
            client_data.useCng = true;
            client_data.cng = client_data.dh.a(client_data.cng); //key is made and in d.keycng.key
            client_data.dh = new ECDHAES256.DH();
            client_data.cng.publicKey = null;
            client_data.cng.bpublicKey = null;
            client_data.cng.bob = null;
            client_data.cng.alice = null;
            return client_data;
        }
        public DATA KeyExchangeBob(DATA d)
        {
            d.stream = d.client.GetStream();
            if (d.client.Connected)
            {
                d.stream = d.client.GetStream();
                //ASYNC RECV
                if (d.useWhisper == true)
                {
                    d.worker = createWhisperWorker();
                }
                else {
                    d.worker = createRecvWorker();
                }
                if (d.useCng == true)
                {
                    d.dh = new ECDHAES256.DH();
                    d.cng = new ECDHAES256.CNG();
                    d.packet = new PACKET();
                    d.packet.bytes = new Byte[4096];
                    Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);
                    d = makePacket(d);
                    if (!d.packet.flag.Equals("INIT")) { return d; }
                    d.cng.bpublicKey = FROMBASE64(d.packet.data);
                    d.cng = d.dh.b(d.cng); //MAKE KEY               

                    d.packet = new PACKET();
                    d.packet.flag = "RET_INIT";
                    d.packet.data = BASE64(d.cng.publicKey);
                    d = Send(d);
                    d.useCng = true;
                    d.dh = null;
                    d.cng.publicKey = null;
                    d.cng.bpublicKey = null;
                    d.cng.bob = null;
                    d.cng.alice = null;
                }
                d.worker.RunWorkerAsync(d);
                return d;
            }
            return d;
        }

        private DATA Task(DATA d)
        {
            try
            {
                d = d.taskFunction(d);
                return d;
            }
            catch (Exception) { return d; }
        }
        public String BASE64(Byte[] datas)
        {
            return Convert.ToBase64String(datas);
        }
        public Byte[] FROMBASE64(String str)
        {
            return Convert.FromBase64String(str);
        }
        public DATA Send(DATA d)
        {

            try
            {
                d.packet.ip = d.client.Client.LocalEndPoint.ToString();
                d.packet.bytes = buildRequest(d.packet);
                if (d.stream.CanWrite) //send alice public key
                {
                    d.stream.Write(d.packet.bytes, 0, d.packet.bytes.Length);
                }
                return d;
            }
            catch (Exception)
            {
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                return d;
            }
        }
        public DATA Recieve(DATA d, int buffer = 512)
        {
            try
            {
                d.packet = new PACKET();
                d.packet.bytes = new Byte[buffer];
                d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);
                d.bytes = d.packet.bytes;
                return d;
            }
            catch (Exception)
            {
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                return d;
            }
        }
        public DATA SendWithCng(DATA d, bool useCompression = false)
        {
            try
            {
                d.cng.plaintextBytes = buildRequest(d.packet);
                ECDHAES256.AES crypto = new ECDHAES256.AES();

                crypto.cng = crypto.encrypt(d.cng);
                d.cng.plaintextBytes = null;
                String IVandENC = BASE64(crypto.cng.iv) + "<SPLIT>" + BASE64(crypto.cng.encryptedBytes);
                if (useCompression)
                {
                    //IV is First 16 bytes
                    IEnumerable<byte> bytes = crypto.cng.iv.Concat(crypto.cng.encryptedBytes);
                    Compression.Compression zipper = new Compression.Compression();
                    d.bytes = zipper.CompressBytesToBytes(bytes.ToArray());

                    //Optionally
                    //ZIP.Compression zip = new ZIP.Compression(bytes.ToArray());
                    //d.bytes = zip.getBytes;
                }
                else
                {
                    d.bytes = new Byte[IVandENC.Length];
                    d.bytes = System.Text.Encoding.ASCII.GetBytes(IVandENC);
                }


                if (d.stream.CanWrite)
                {
                    d.stream.Write(d.bytes, 0, d.bytes.Length);
                }
                d.packet = new PACKET();
                d.bytes = null;
                d.cng.iv = null;
                d.cng.plaintextBytes = null;
                d.cng.encryptedBytes = null;
                return d;
            }
            catch (Exception)
            {
                d.packet = new PACKET();
                d.bytes = null;
                d.cng.iv = null;
                d.cng.encryptedBytes = null;
                d.useCng = false;
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                return d;
            }

        }
        public DATA SendWhisper(DATA d)
        {
            try
            {
                d.cng.plaintextBytes = buildRequest(d.packet);
                d.whisp = new WhisperProtocol.Whisp();
                d.whisp.cng = d.cng;
                d.whisp = d.whisperer.whisper(d.whisp);
                d.cng = d.whisp.cng; //update cng
                if (d.stream.CanWrite)
                {
                    d.stream.Write(d.whisp.bytes, 0, d.whisp.bytes.Length);
                }
                d.Clean();
                return d;
            }
            catch (Exception)
            {
                d.Clean();
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                return d;
            }
        }
        private void whisper_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Argument;
                d.packet = new PACKET();

                d.packet.bytes = new Byte[d.RecieveBufferSize];
                Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);

                d.whisp.bytes = new byte[i];
                for (int c = 0; c < i; ++c)
                {
                    d.whisp.bytes[c] = d.packet.bytes[c];
                }

                //prepare cng with current key
                d.whisp.cng = d.cng; //only for ratchet
                //Listen
                d.whisp = d.whisperer.listen(d.whisp);
                //update cng with ratchet key
                d.cng = d.whisp.cng; //only for ratchet
                //Return Packet Data
                d.packet.bytes = d.whisp.bytes;
                e.Result = d;
            }
            catch (Exception)
            {
                DATA d = (DATA)e.Argument;
                d.IsConnected = false;
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                else if (faultfunction != null)
                { d = faultfunction(d); }
                e.Result = d;
            }
        }
        private void whisper_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Result;

                d = makePacket(d);
                if (!d.packet.length.Equals("-1")) //safety
                {
                    if (d.taskFunction != null)
                    { d = Task(d); }
                }
                d.packet = new PACKET();
                if (!e.Cancelled)
                    d.worker.RunWorkerAsync(d);
            }
            catch (Exception)
            {
                DATA d = (DATA)e.Result;
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                else if (faultfunction != null)
                { d = faultfunction(d); }
                if (!e.Cancelled)
                { d.worker.RunWorkerAsync(d); }
            }
        }
        private void worker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Argument;
                d.packet = new PACKET();
                d.packet.bytes = new Byte[d.RecieveBufferSize];
                Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);
                if (d.useCompression == true && d.useCng == true)
                {
                    Compression.Compression zipper = new Compression.Compression();
                    d.packet.bytes = zipper.DeCompressBytesToBytes(d.packet.bytes, d.packet.bytes.Length * 2);
                    d.cng.encryptedBytes = null;
                    d.cng.iv = new byte[16];
                    for (int c = 0; c < 16; ++c)
                    {
                        d.cng.iv[c] = d.packet.bytes[c];
                    }
                    d.packet.bytes.CopyTo(d.cng.encryptedBytes, 16);
                    //shorten enc
                }
                e.Result = d;
            }
            catch (Exception)
            {
                DATA d = (DATA)e.Argument;
                d.IsConnected = false;
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                else if (faultfunction != null)
                { d = faultfunction(d); }
                e.Result = d;
            }
        }
        private void worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Result;
                if (d.useCng && d.useCompression)
                {
                    d = makeCngPacket(d);
                }
                else
                {
                    d = makePacket(d);
                }
                if (!d.packet.length.Equals("-1")) //safety
                {
                    if (d.taskFunction != null)
                    { d = Task(d); }
                }
                d.packet = new PACKET();
                if (!e.Cancelled)
                    d.worker.RunWorkerAsync(d);
            }
            catch (Exception)
            {
                DATA d = (DATA)e.Result;
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                else if (faultfunction != null)
                { d = faultfunction(d); }
            }
        }


    }
}
namespace Whisper_Client_Package
{
    using System;
    using System.Net.Sockets;
    using System.ComponentModel;
    public struct PACKET
    {
        public String ip;
        public String arg;
        public String length;
        public String flag;
        public String data;
        public Byte[] bytes;
    }
    public struct DATA
    {
        public void Clean()
        {
            try
            {
                packet = new PACKET();
                bytes = null;
                cng.iv = null;
                cng.plaintextBytes = null;
                cng.encryptedBytes = null;
            }
            catch (Exception)
            { }
        }
        public bool useCompression;
        public bool useWhisper;
        public WhisperProtocol.Whisperer whisperer;
        public WhisperProtocol.Whisp whisp;
        public Int32 RecieveBufferSize;
        public BackgroundWorker worker;
        public Func<DATA, DATA> faultFunction;
        public Func<DATA, DATA> taskFunction;
        public PACKET packet;
        public String RHOST;
        public Int32 RPORT;
        public TcpClient client;
        public NetworkStream stream;
        public String data;
        public Byte[] bytes;
        public String host;
        public String port;
        public ECDHAES256.CNG cng;
        public bool useCng;
        public ECDHAES256.DH dh;
        public bool IsConnected;
    }
    public class CLIENT_COM
    {

        public DATA data;

        public Func<DATA, DATA> FaultFunction { get; set; }
        public CLIENT_COM()
        {

            data = new DATA();
            DATA d = new DATA();
            d.RHOST = "127.0.0.1";
            d.RPORT = 10101;
            data = d;
        }
        private static String addHEAD(int data, PACKET packet)
        {
            String[] HEADER = new String[6];
            HEADER[0] = "<START>";
            HEADER[1] = "<IP>" + packet.ip;
            HEADER[2] = "<ARG>" + packet.arg;
            HEADER[3] = "<LENGTH>" + System.Convert.ToString(data);
            HEADER[4] = "<FLAG>" + packet.flag;
            HEADER[5] = "<DATA>";
            return HEADER[0] + HEADER[1] + HEADER[2] + HEADER[3] + HEADER[4] + HEADER[5];
        }
        private static String addFOOT()
        {
            return "<END>";
        }
        private static Byte[] buildRequest(PACKET packet)
        {
            //CAN ADD AES HERE TO ENCRPYT PACKET BEFORE RETURN
            if (packet.data == null)
            {
                String PACKET = addHEAD(0, packet) + addFOOT();
                return System.Text.Encoding.ASCII.GetBytes(PACKET);

            }
            else {
                String PACKET = addHEAD(packet.data.Length, packet) + packet.data + addFOOT();
                return System.Text.Encoding.ASCII.GetBytes(PACKET);

            }
        }
        private static DATA makePacket(DATA d)
        {
            try
            {
                String dat = System.Text.Encoding.ASCII.GetString(d.packet.bytes, 0, d.packet.bytes.Length);
                d.bytes = d.packet.bytes;
                d.packet = new PACKET();
                if (dat.Contains("<SPLIT>"))
                {
                    dat = dat.Replace("<SPLIT>", "~");
                    String[] tmp = dat.Split('~');
                    d.cng.iv = Convert.FromBase64String(tmp[0]);
                    tmp = tmp[1].Split('\0');
                    d.cng.encryptedBytes = Convert.FromBase64String(tmp[0]);
                    tmp = null;

                    ECDHAES256.AES crypto = new ECDHAES256.AES();
                    crypto.cng = crypto.decrypt(d.cng); //TODO PROBLEM HERE
                    d.cng.plaintextBytes = crypto.cng.plaintextBytes;

                    dat = System.Text.Encoding.ASCII.GetString(d.cng.plaintextBytes, 0, d.cng.plaintextBytes.Length);
                    d.cng.plaintextBytes = null;
                    d.cng.encryptedBytes = null;
                    d.cng.iv = null;
                }
                if (dat.Contains("<ARG>") && dat.Contains("<LENGTH>") && dat.Contains("<FLAG>") && dat.Contains("<DATA>") && dat.Contains("<END>"))
                {
                    try
                    {
                        String[] valid = { "<ARG>", "<LENGTH>", "<FLAG>", "<DATA>", "<END>" };
                        dat = dat.Replace("<START>", "");
                        dat = dat.Replace("<IP>", "");
                        int i;
                        for (i = 0; i < valid.Length; ++i)
                        {
                            dat = dat.Replace(valid[i], "~");
                        }
                        String[] dd = dat.Split('~');
                        if (dd.Length > 1)
                        {
                            d.packet.ip = dd[0];
                            d.packet.arg = dd[1];
                            d.packet.length = dd[2];
                            d.packet.flag = dd[3];
                            d.packet.data = dd[4];
                        }
                        else {
                            d.packet.arg = "";
                            d.packet.ip = "";
                            d.packet.length = "-1";
                            d.packet.flag = "";
                            d.packet.data = "";
                        }
                        return d;
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("\nError in makePacket");
                        PACKET pack = new PACKET();
                        pack.arg = "";
                        pack.ip = "";
                        pack.length = "-1";
                        pack.flag = "";
                        pack.data = "";
                        d.packet = pack;
                    }
                }
            }
            catch (Exception)
            { d.packet = new PACKET(); d.packet.length = "-1"; }
            return d;
        }
        private DATA Task(DATA d)
        {
            try
            {
                d = d.taskFunction(d);
                return d;
            }
            catch (Exception) { return d; }
        }
        private static void worker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Argument;
                d.packet = new PACKET();
                d.packet.bytes = new Byte[40960];
                Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);

                e.Result = d;
            }
            catch (Exception) { e.Result = (DATA)e.Argument; } // add -1 for error server disconnected
        }
        private static void worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Result;
                String dat = System.Text.Encoding.ASCII.GetString(d.packet.bytes, 0, d.packet.bytes.Length);

                d = makePacket(d);
                if (!d.packet.length.Equals("-1")) //safety
                {
                    if (d.taskFunction != null)
                    { d = d.taskFunction(d); }
                }
                d.packet = new PACKET();
                if (d.worker != null)
                { d.worker.RunWorkerAsync(d); }
                else
                {
                    d.client.Close();
                    if (d.faultFunction != null)
                    { d = d.faultFunction.Invoke(d); }
                    Console.WriteLine("\nPROGRAM HALT connection fault");
                }

            }
            catch (Exception)
            {
                Console.WriteLine("\nERROR connection dropped in RunWorkerCompleted");
                DATA d = (DATA)e.Result;
                if (d.faultFunction != null)
                { d = d.faultFunction.Invoke(d); }
            }
        }
        private static BackgroundWorker createRecvWorker()
        {
            //Program p = new Program(); //possible problem
            BackgroundWorker backgroundWorker1 = new BackgroundWorker();
            backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(worker_DoWork);
            backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(worker_RunWorkerCompleted);
            return backgroundWorker1;
        }
        public BackgroundWorker createWhisperWorker()
        {
            //Program p = new Program(); //possible problem
            BackgroundWorker backgroundWorker1 = new BackgroundWorker();
            backgroundWorker1.WorkerSupportsCancellation = true;
            backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(whisper_DoWork);
            backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(whisper_RunWorkerCompleted);
            return backgroundWorker1;
        }
        private byte[] trimByte(byte[] input)
        {
            if (input.Length > 1)
            {
                int byteCounter = input.Length - 1;
                while (input[byteCounter] == 0x00)
                {
                    byteCounter--;
                }
                byte[] rv = new byte[(byteCounter + 1)];
                for (int byteCounter1 = 0; byteCounter1 < (byteCounter + 1); byteCounter1++)
                {
                    rv[byteCounter1] = input[byteCounter1];
                }
                return rv;
            }
            else { return input; }
        }
        private static String packetToString(PACKET p)
        {
            return "<START>" + "<IP>" + p.ip + "<ARG>" + p.arg + "<LENGTH>" + p.length + "<FLAG>" + p.flag + "<DATA>" + p.data + "<END>";
        }
        private static String BASE64(Byte[] datas)
        {
            return Convert.ToBase64String(datas);
        }
        private static Byte[] FROMBASE64(String str)
        {
            return Convert.FromBase64String(str);
        }
        public DATA Send(DATA d)
        {


            d.packet.ip = d.client.Client.LocalEndPoint.ToString();
            d.packet.bytes = buildRequest(d.packet);
            if (d.stream.CanWrite) //send alice public key
            {
                d.stream.Write(d.packet.bytes, 0, d.packet.bytes.Length);
            }
            return d;
        }

        public DATA SendWhisper(DATA d)
        {
            try
            {
                d.cng.plaintextBytes = buildRequest(d.packet);
                d.whisp = new WhisperProtocol.Whisp();
                d.whisp.cng = d.cng;
                d.whisp = d.whisperer.whisper(d.whisp);
                d.cng = d.whisp.cng; //update cng
                if (d.stream.CanWrite)
                {
                    d.stream.Write(d.whisp.bytes, 0, d.whisp.bytes.Length);
                }
                d.Clean();
                return d;
            }
            catch (Exception)
            {
                d.Clean();
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                return d;
            }
        }
        private void whisper_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Argument;
                d.packet = new PACKET();

                d.packet.bytes = new Byte[d.RecieveBufferSize];
                Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);

                d.whisp.bytes = new byte[i];
                for (int c = 0; c < i; ++c)
                {
                    d.whisp.bytes[c] = d.packet.bytes[c];
                }

                //prepare cng with current key
                d.whisp.cng = d.cng; //only for ratchet
                //Listen
                d.whisp = d.whisperer.listen(d.whisp);
                //update cng with ratchet key
                d.cng = d.whisp.cng; //only for ratchet
                //Return Packet Data
                d.packet.bytes = d.whisp.bytes;
                e.Result = d;
            }
            catch (Exception)
            {
                DATA d = (DATA)e.Argument;
                d.IsConnected = false;
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                else if (FaultFunction != null)
                { d = FaultFunction(d); }
                e.Result = d;
            }
        }
        private void whisper_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Result;

                d = makePacket(d);
                if (!d.packet.length.Equals("-1")) //safety
                {
                    if (d.taskFunction != null)
                    { d = Task(d); }
                }
                d.packet = new PACKET();
                if (!e.Cancelled)
                    d.worker.RunWorkerAsync(d);
            }
            catch (Exception)
            {
                DATA d = (DATA)e.Result;
                if (d.faultFunction != null)
                { d = d.faultFunction(d); }
                else if (FaultFunction != null)
                { d = FaultFunction(d); }
            }
        }
        public DATA Connect(DATA d)
        {
            try
            {
                if (d.useWhisper == true)
                {
                    d.whisperer = new WhisperProtocol.Whisperer();
                    d.whisp = new WhisperProtocol.Whisp();
                }
                d.useCng = true;
                d.client = new TcpClient(d.RHOST, d.RPORT);
            }
            catch (Exception) { Console.WriteLine("\nERROR connecting to Server"); System.Threading.Thread.Sleep(2000); d = Connect(d); return d; }
            return d;

        }
        public DATA keyExchangeAlice(DATA client_data)
        {

            client_data.dh = new ECDHAES256.DH();
            client_data.cng = new ECDHAES256.CNG();
            client_data.cng = client_data.dh.a(client_data.cng);
            client_data.packet = new PACKET();
            client_data.packet.flag = "INIT";
            client_data.packet.data = BASE64(client_data.cng.publicKey);
            client_data = Send(client_data);
            client_data.packet = new PACKET();
            client_data.packet.bytes = new Byte[4096];
            Int32 i = client_data.stream.Read(client_data.packet.bytes, 0, client_data.packet.bytes.Length);
            client_data = makePacket(client_data);
            if (!client_data.packet.flag.Equals("RET_INIT")) { }
            client_data.cng.bpublicKey = FROMBASE64(client_data.packet.data); //remote bob local alice meet
            client_data.useCng = true;
            client_data.cng = client_data.dh.a(client_data.cng); //key is made and in d.keycng.key
            client_data.dh = null;
            client_data.cng.publicKey = null;
            client_data.cng.bpublicKey = null;
            client_data.cng.bob = null;
            client_data.cng.alice = null;
            return client_data;
        }
        public DATA KeyExchangeBob(DATA d, bool useCng = true)
        {
            d.stream = d.client.GetStream();
            if (d.client.Connected)
            {
                d.stream = d.client.GetStream();
                //ASYNC RECV
                if (d.useWhisper == true)
                {
                    d.worker = createWhisperWorker();
                }
                else {
                    d.worker = createRecvWorker();
                }
                if (useCng == true)
                {
                    d.dh = new ECDHAES256.DH();
                    d.cng = new ECDHAES256.CNG();
                    d.packet = new PACKET();
                    d.packet.bytes = new Byte[4096];
                    Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);
                    d = makePacket(d);
                    if (!d.packet.flag.Equals("INIT")) { return d; }
                    d.cng.bpublicKey = FROMBASE64(d.packet.data);
                    d.cng = d.dh.b(d.cng); //MAKE KEY               

                    d.packet = new PACKET();
                    d.packet.flag = "RET_INIT";
                    d.packet.data = BASE64(d.cng.publicKey);
                    d = Send(d);
                    d.useCng = true;
                    d.dh = null;
                    d.cng.publicKey = null;
                    d.cng.bpublicKey = null;
                    d.cng.bob = null;
                    d.cng.alice = null;
                }
                d.worker.RunWorkerAsync(d);
                return d;
            }
            return d;
        }
    }
}
namespace WhisperProtocol
{
    using Compression;
    using ECDHAES256;
    using System.IO;
    public struct Whisp
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
        public string aname;
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

        /*A Whsiper is an AES256 encrypting packet protocol defined as *******************************************
        *   speak() encapsulates compresses and encrypts
        *   listen() decrypts decompresses and decapsulates
        *   4 byte Int32 for compressed payload size
        *   4 byte Int32 for original uncompressed size of payload
        *   140 byte for public key
        *   rest is Payload
        *   
        *   provide 256 bit key in Whisp.cng.key USES: ECDHAES2
        *
        *   returned is aes.cng.encryptedBytes appended to the aes.cng.iv
        *
        ***************************************************************************************/
        public Whisp whisp;

        /// <summary>Whisper Softly [4 byte Int32 for compressed payload size in bytes]+[4 byte Int32 for original payload size in bytes]+[Payload]</summary>
        public Whisperer()
        {
            whisp = new Whisp();
            whisp.dh = new DH();
            whisp.aes = new AES();
            whisp.compression = new Compression();
            whisp.cng = new CNG();
            whisp.ratchet = new Ratchet();
            whisp.ratchet.dh = new DH();
        }
        /// <summary>Speak in a Whisper..Supply whisper.cng.key and whsiper.cng.plaintextBytes</summary>
        /// <param name="whisp"> Supply whisper.cng.key and whsiper.cng.plaintextBytes</param>
        public Whisp whisper(Whisp whisp)
        {
            try
            {
                //whisp = readyRatchet(whisp); //public key ready for next dh exchange
                whisp = ratchet(whisp);
                whisp.publicKey = whisp.ratchet.cng.publicKey;
                if (whisp.cng.plaintextBytes == null && whisp.bytes != null)
                {
                    whisp.cng.plaintextBytes = whisp.bytes;
                }
                //Label Compression Original Size
                whisp.compressionSize = BitConverter.GetBytes(whisp.cng.plaintextBytes.Length);
                //Compress
                whisp.compression = new Compression();
                byte[] compressedBytes = whisp.compression.CompressBytesToBytes(whisp.cng.plaintextBytes);
                //label Compressed message size             
                whisp.messageSize = BitConverter.GetBytes(compressedBytes.Length); //PLUS 2 for HEADER
                //MAKE READY PACKET *** ADD PUBLIC KEY ***
                IEnumerable<byte> result = whisp.messageSize.Concat(whisp.compressionSize).Concat(whisp.publicKey).Concat(compressedBytes);
                whisp.cng.plaintextBytes = result.ToArray(); //header is first 8+140 bytes
                //Encrypt PACKET
                whisp.aes = new AES();
                whisp.cng = whisp.aes.encrypt(whisp.cng);
                //Return Whisp, 
                IEnumerable<byte> result2 = whisp.cng.iv.Concat(whisp.cng.encryptedBytes);
                whisp.bytes = result2.ToArray();
                whisp.ratchet.aliceReady = true;
                if (whisp.ratchet.aliceReady && whisp.ratchet.bobReady)
                { whisp = ratchet(whisp); }
                whisp.Clean();

                return whisp;
            }
            catch (Exception e)
            {
                whisp.obj = e;
                return whisp;
            }
        } //you supply whisp.cng
        /// <summary>Listen to a Whisper..Supply whisper.cng.key and whisper.cng.encryptedBytes</summary>
        /// <param name="whisper"> Supply whisper.cng.key and whisper.cng.encryptedBytes</param>
        public Whisp listen(Whisp whisper)
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
        private Whisp primeRatchet(Whisp whisp)
        {
            try
            {
                if (whisp.ratchetIsPrimmed == false)
                {
                    whisp.ratchet.dh = new DH();
                    if (whisp.publicKey != null)//whisp.ratchet.cng.key== null &&
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
        private Whisp ratchet(Whisp whisp)
        {
            try
            {
                //whisp.ratchet.cng.alice == null && whisp.ratchet.cng.publicKey==null
                if (whisp.ratchetIsPrimmed == false) //IF this is the first ratchet
                {
                    whisp = primeRatchet(whisp); //aliceReady is still false until first send
                }
                if (whisp.ratchet.aliceReady == true && whisp.ratchet.bobReady == true) //both sides ready to ratchet
                {//alice must be present and bpublic key must be present
                    //PROBLEM BOB JUST SEND PK
                    if (whisp.ratchet.cng.key == null)
                    {
                        whisp.ratchet.cng.bpublicKey = whisp.publicKey;
                        whisp.ratchet.cng = whisp.ratchet.dh.a(whisp.ratchet.cng); //makes key
                    }
                    else if (whisp.ratchet.cng.key != null)
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
        public byte[] key { get; private set; }
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
                {
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        encryptedMessage = ciphertext.ToArray();
                    }
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
        public byte[] CompressBytesToBytes(byte[] inBuffer)
        {
            using (MemoryStream resultStream = new MemoryStream())
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                         CompressionMode.Compress))
                {
                    compressionStream.Write(inBuffer, 0, inBuffer.Length);
                }
                return resultStream.ToArray();
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
namespace Identify
{
    using System;
    using System.Text;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.NetworkInformation;
    using System.Security.Cryptography;
    public class IDmaker
    {
        public String hash { get; private set; }
        public IDmaker()
        {
            try
            {
                var macs = GetMACAddresses();
                String prehash = "";
                foreach (var mac in macs)
                {
                    prehash += mac;
                }
                hash = getMD5Hash(prehash);
            }
            catch (Exception)
            {
                hash = "0000000000000000000";
                Console.WriteLine("\nError in IDmaker");
            }
        }
        public UInt64 getHash(String key)
        {
            char[] p = key.ToArray();
            UInt64 h = 2166136261;
            int i;

            for (i = 0; i < key.Length; i++)
            {
                h = (h * 16777619) ^ p[i];
            }

            return h;
        }
        public string getMD5Hash(string input)
        {
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hash = md5.ComputeHash(inputBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
                //sb.Append(String.Format("{0:X2}", hash[i]));
            }
            return sb.ToString();
        }
        public IEnumerable<String> GetMACAddresses()
        {
            var macAddr =
                (
                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up
                    select nic.GetPhysicalAddress().ToString()
                );

            return macAddr.ToList();
        }
    }
}