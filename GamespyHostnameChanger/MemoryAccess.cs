using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using RGiesecke.DllExport;

public static class MemoryAccess
{
    private const Int32 PROC_RW = 0x1F0FFF;
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, Int32 lpBaseAddress, [Out()]byte[] lpBuffer, int dwSize, ref IntPtr lpNumberOfBytesRead);
    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess, Int32 lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);

    public static Int32 BaseAddress { get; set; }

    private static Process proc;
    private static IntPtr procHwnd;

    [DllExport("LoadProcess", CallingConvention = CallingConvention.Cdecl)]
    public static bool LoadProcess(string applicationPath, bool ignoreCase = false)
    {
        string processName = Path.GetFileNameWithoutExtension(applicationPath);
        foreach (Process p in Process.GetProcessesByName(processName))
        {
            if (ignoreCase)
            {
                if (p.MainModule.FileName.ToLower().Equals(applicationPath.ToLower()))
                    proc = p;
            }
            else
            {
                if (p.MainModule.FileName.Equals(applicationPath))
                    proc = p;
            }
        }

        if (proc == null) return false;
        BaseAddress = (Int32)proc.MainModule.BaseAddress;
        procHwnd = OpenProcess(PROC_RW, false, proc.Id);
        if (procHwnd.Equals(IntPtr.Zero)) return false;
        return true;
    }

    [DllExport("CloseProcess", CallingConvention = CallingConvention.Cdecl)]
    public static void CloseProcess()
    {
        if (!procHwnd.Equals(IntPtr.Zero))
            CloseHandle(procHwnd);
        proc = null;
        procHwnd = IntPtr.Zero;
    }

    [DllExport("ReadByte", CallingConvention = CallingConvention.Cdecl)]
    public static byte ReadByte(Int32 address)
    {
        byte[] buf = null;
        ReadBuffer(address, ref buf, 1);
        return buf[0];
    }

    [DllExport("ReadInt16", CallingConvention = CallingConvention.Cdecl)]
    public static Int16 ReadInt16(Int32 address)
    {
        byte[] buf = null;
        ReadBuffer(address, ref buf, 2);
        return BitConverter.ToInt16(buf, 0);
    }

    [DllExport("ReadInt32", CallingConvention = CallingConvention.Cdecl)]
    public static Int32 ReadInt32(Int32 address)
    {
        byte[] buf = null;
        ReadBuffer(address, ref buf, 4);
        return BitConverter.ToInt32(buf, 0);
    }

    [DllExport("ReadInt64", CallingConvention = CallingConvention.Cdecl)]
    public static Int64 ReadInt64(Int32 address)
    {
        byte[] buf = null;
        ReadBuffer(address, ref buf, 8);
        return BitConverter.ToInt64(buf, 0);
    }

    [DllExport("ReadFloat", CallingConvention = CallingConvention.Cdecl)]
    public static float ReadFloat(Int32 address)
    {
        byte[] buf = null;
        ReadBuffer(address, ref buf, 4);
        return BitConverter.ToSingle(buf, 0);
    }

    [DllExport("ReadDouble", CallingConvention = CallingConvention.Cdecl)]
    public static double ReadDouble(Int32 address)
    {
        byte[] buf = null;
        ReadBuffer(address, ref buf, 8);
        return BitConverter.ToDouble(buf, 0);
    }

    [DllExport("ReadString", CallingConvention = CallingConvention.Cdecl)]
    public static string ReadString(Int32 address, int len, bool autoTrim = false)
    {
        byte[] buf = null;
        ReadBuffer(address, ref buf, len);
        string str = System.Text.Encoding.ASCII.GetString(buf);
        if (autoTrim) str = str.TrimEnd((char)0);
        return str;
    }

    [DllExport("WriteByte", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteByte(Int32 address, byte value)
    {
        WriteBuffer(address, BitConverter.GetBytes(value));
    }

    [DllExport("WriteInt16", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteInt16(Int32 address, Int16 value)
    {
        WriteBuffer(address, BitConverter.GetBytes(value));
    }

    [DllExport("WriteInt32", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteInt32(Int32 address, Int32 value)
    {
        WriteBuffer(address, BitConverter.GetBytes(value));
    }

    [DllExport("WriteInt64", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteInt64(Int32 address, Int64 value)
    {
        WriteBuffer(address, BitConverter.GetBytes(value));
    }

    [DllExport("WriteFloat", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteFloat(Int32 address, float value)
    {
        WriteBuffer(address, BitConverter.GetBytes(value));
    }

    [DllExport("WriteDouble", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteDouble(Int32 address, double value)
    {
        WriteBuffer(address, BitConverter.GetBytes(value));
    }

    [DllExport("WriteString", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteString(Int32 address, string str)
    {
        byte[] buf = System.Text.Encoding.ASCII.GetBytes(str);
        WriteBuffer(address, buf);
    }

    [DllExport("ReadAddress", CallingConvention = CallingConvention.Cdecl)]
    public static Int32 ReadAddress(Int32 address, Int32 offset = 0)
    {
        Int32 addr = (Int32)proc.MainModule.BaseAddress + address;
        addr = ReadInt32(addr);
        addr += offset;
        return addr;
    }

    [DllExport("ClearMem", CallingConvention = CallingConvention.Cdecl)]
    public static void ClearMem(Int32 address, Int32 len)
    {
        byte[] buf = new byte[len];
        WriteBuffer(address, buf);
    }

    [DllExport("WriteBuffer", CallingConvention = CallingConvention.Cdecl)]
    public static void WriteBuf(Int32 address, byte[] buffer)
    {
        WriteBuffer(address, buffer);
    }

    public static void WriteBuffer(Int32 address, byte[] buffer)
    {
        IntPtr bytesWritten = IntPtr.Zero;
        WriteProcessMemory(procHwnd, address + BaseAddress, buffer, buffer.Length, ref bytesWritten);
    }

    [DllExport("ReadBuffer", CallingConvention = CallingConvention.Cdecl)]
    public static void ReadBuf(Int32 address, ref byte[] buffer, int len)
    {
        ReadBuffer(address, ref buffer, len);
    }

    public static void ReadBuffer(Int32 address, ref byte[] buffer, int len)
    {
        buffer = new byte[len];
        IntPtr bytesRead = IntPtr.Zero;
        ReadProcessMemory(procHwnd, address + BaseAddress, buffer, buffer.Length, ref bytesRead);
    }
}