using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AnimeStudio.Crypto
{
    public static class HYGUtils
    {
        // === 目标 RVA（按你的样本填写） ===
        public const ulong RVA_DecryptFn = 0x0000000001091810UL; // sub_181091810
        public const ulong RVA_StreamKeyPoolPtr = 0x0000000001FD27D0UL; // qword_181FD27D0
        private static byte[] StreamKeyPool = {
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
            0x96, 0x52, 0x97, 0x7B, 0x13, 0xD0, 0x84, 0xF8, 0x72, 0x1E, 0xBC, 0x10, 0x87, 0xFF, 0xDB, 0xA3,
            0xB6, 0x14, 0x22, 0x35, 0x0A, 0x23, 0x0F, 0x13, 0x21, 0x85, 0x2A, 0xB6, 0xA8, 0x7A, 0xCE, 0x23,
        };

        // ===== WinAPI =====
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr GetModuleHandleW(string? name);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibraryW(string path);

        [DllImport("kernel32", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);

        [DllImport("kernel32", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint allocType, uint prot);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate byte DecryptHeaderFn(IntPtr buf, uint len, IntPtr key16);

        private static IntPtr sModule;
        private static DecryptHeaderFn? sDecrypt;


        /// <summary>加载模块，解析函数地址。</summary>
        public static bool Init(string moduleName = "HYG_UnityPlayer.dll")
        {
            if (sModule != IntPtr.Zero) // 已经初始化过了
            {
                return true;
            }

            sModule = GetModuleHandleW(moduleName);
            if (sModule == IntPtr.Zero) sModule = LoadLibraryW(moduleName);
            if (sModule == IntPtr.Zero) { Log($"[!] Load/GetModuleHandle failed: {moduleName}"); return false; }

            var fnPtr = IntPtr.Add(sModule, (int)RVA_DecryptFn);
            sDecrypt = Marshal.GetDelegateForFunctionPointer<DecryptHeaderFn>(fnPtr);

            _ = TryPrimeStreamKeyPool(StreamKeyPool);

            return sDecrypt != null;
        }

        /// <summary>就地解密：对 32B 缓冲调用原生解密（key16 = keyB(8) || keyA(8)）。</summary>
        public unsafe static bool DecryptHeaderInPlace(Span<byte> buf32, ulong keyB, ulong keyA_zext)
        {
            if (buf32.Length != 32) throw new ArgumentException("buf32 must be 32 bytes.");
            if (sDecrypt == null && !Init()) return false;

            var key = stackalloc byte[16];
            WriteU64(key, 0, keyB);
            WriteU64(key, 8, keyA_zext);

            // pin + 调用
            unsafe
            {
                fixed (byte* pBuf = buf32)
                {
                    byte ok = sDecrypt!((IntPtr)pBuf, 32, (IntPtr)key);
                    return ok != 0;
                }
            }
        }

        public static bool PredecodeInPlace(Span<byte> buffer, ulong keyB, ulong keyA_zext)
        {
            if (buffer.Length == 0) return true; // 空块直接视为成功
            if (sDecrypt == null && !Init()) return false;

            // 原生调用路径里最终长度会作为 int/uint 传给 LZ4，所以这里也限制到 int 范围
            if (buffer.Length >= 0x7FFFFFFF)
                throw new ArgumentOutOfRangeException(nameof(buffer), "length too large");

            // 1) 准备 16B key（LE）：keyB @ [0..7], keyA_zext @ [8..15]
            var keyArr = new byte[16];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(keyArr.AsSpan(0, 8), keyB);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(keyArr.AsSpan(8, 8), keyA_zext);

            // 2) 分配非托管内存并拷贝数据
            IntPtr keyMem = IntPtr.Zero, bufMem = IntPtr.Zero;
            try
            {
                keyMem = Marshal.AllocHGlobal(16);
                Marshal.Copy(keyArr, 0, keyMem, 16);

                bufMem = Marshal.AllocHGlobal(buffer.Length);
                var tmpIn = buffer.ToArray();
                Marshal.Copy(tmpIn, 0, bufMem, buffer.Length);

                // 3) 调用同一个底层原生函数（它支持任意长度）
                byte ok = sDecrypt!(bufMem, (uint)buffer.Length, keyMem);
                if (ok == 0) return false;

                // 4) 回拷
                var tmpOut = new byte[buffer.Length];
                Marshal.Copy(bufMem, tmpOut, 0, buffer.Length);
                tmpOut.CopyTo(buffer);
                return true;
            }
            finally
            {
                if (bufMem != IntPtr.Zero) Marshal.FreeHGlobal(bufMem);
                if (keyMem != IntPtr.Zero) Marshal.FreeHGlobal(keyMem);
            }
        }


        /// <summary>返回新数组的便捷封装。</summary>
        public static byte[] DecryptHeader(byte[] enc32, ulong keyB, ulong keyA_zext)
        {
            var tmp = (byte[])enc32.Clone();
            if (!DecryptHeaderInPlace(tmp, keyB, keyA_zext))
                throw new InvalidOperationException("decrypt header failed.");
            return tmp;
        }

        public static bool TryPrimeStreamKeyPool(ReadOnlySpan<byte> dump256)
        {
            if (dump256.Length != 256) return false;
            var poolPtrP = IntPtr.Add(sModule, (int)RVA_StreamKeyPoolPtr);
            // 读取现有指针
            IntPtr cur = Marshal.ReadIntPtr(poolPtrP);

            if (cur != IntPtr.Zero)
            {
                if (!SetWritable(cur, (UIntPtr)256, out var oldProt)) return false;
                unsafe { fixed (byte* p = dump256) Marshal.Copy(dump256.ToArray(), 0, cur, 256); }
                VirtualProtect(cur, (UIntPtr)256, oldProt, out _);
                return true;
            }
            else
            {
                IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)256,
                    0x1000 /*MEM_COMMIT*/ | 0x2000 /*MEM_RESERVE*/, 0x04 /*PAGE_READWRITE*/);
                if (buf == IntPtr.Zero) { Log("[!] VirtualAlloc failed"); return false; }
                Marshal.Copy(dump256.ToArray(), 0, buf, 256);
                if (!SetWritable(poolPtrP, (UIntPtr)IntPtr.Size, out var oldProt2)) return false;
                Marshal.WriteIntPtr(poolPtrP, buf);
                VirtualProtect(poolPtrP, (UIntPtr)IntPtr.Size, oldProt2, out _);
                return true;
            }
        }

        private static unsafe void WriteU64(byte* p, int off, ulong v)
        {
            unchecked
            {
                *(uint*)(p + off + 0) = (uint)(v & 0xFFFFFFFFUL);
                *(uint*)(p + off + 4) = (uint)((v >> 32) & 0xFFFFFFFFUL);
            }
        }

        private static bool SetWritable(IntPtr addr, UIntPtr size, out uint oldProt)
            => VirtualProtect(addr, size, 0x04 /*PAGE_READWRITE*/, out oldProt);

        private static void Log(string s) => Console.WriteLine(s);
    }
}
