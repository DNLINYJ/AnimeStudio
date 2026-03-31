using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AnimeStudio
{
    /// <summary>
    /// Encrypted header fields present when flags &amp; 0x400 is set.
    /// Layout (after flags):
    ///   u32 BE        extra_field
    ///   16 bytes      a4 ciphertext
    ///   16 bytes      a4 counter (AES-CTR IV)
    ///   1 byte        null terminator
    ///   16 bytes      a5 ciphertext
    ///   16 bytes      a5 counter (AES-CTR IV)
    ///   1 byte        null terminator
    /// a5 decrypts to "#$manjuuunity*!@" (verification magic).
    /// a4 decrypts to permutation table + extra params (nibble-encoded).
    ///
    /// Nonce-reuse vulnerability: a4 and a5 share the same counter in
    /// all observed bundles, enabling keyless a4 plaintext recovery via:
    ///   keystream = a5_ct XOR "#$manjuuunity*!@"
    ///   a4_pt     = keystream XOR a4_ct
    /// </summary>
    public class ManjuuHeader
    {
        public uint ExtraField;
        public byte[] A4Ciphertext = new byte[16];
        public byte[] A4Counter    = new byte[16];
        public byte[] A5Ciphertext = new byte[16];
        public byte[] A5Counter    = new byte[16];
    }

    public static class ManjuuUtils
    {
        // sub_1806A5400: aManjuuunityArc[0..15] == "#$manjuuunity*!@"
        private static readonly byte[] MagicVerify = Encoding.ASCII.GetBytes("#$manjuuunity*!@");

        /// <summary>Read the Manjuu-specific extra fields from the bundle header.</summary>
        public static ManjuuHeader ReadHeader(EndianBinaryReader reader)
        {
            var h = new ManjuuHeader();
            h.ExtraField    = reader.ReadUInt32();
            h.A4Ciphertext  = reader.ReadBytes(16);
            h.A4Counter     = reader.ReadBytes(16);
            reader.Position += 1; // null terminator
            h.A5Ciphertext  = reader.ReadBytes(16);
            h.A5Counter     = reader.ReadBytes(16);
            reader.Position += 1; // null terminator
            Logger.Verbose($"[Manjuu] extra_field=0x{h.ExtraField:X8}  a4_ctr={BitConverter.ToString(h.A4Counter).Replace("-","")}  a5_ctr={BitConverter.ToString(h.A5Counter).Replace("-","")}");
            return h;
        }

        /// <summary>
        /// Keyless CTR nonce-reuse attack (no AES key required).
        /// Works when a4 and a5 share the same counter (observed in all CB2 bundles).
        /// Returns (permTable[16], extraParams[16]).
        /// </summary>
        public static (byte[] PermTable, byte[] ExtraParams) RecoverKeyless(ManjuuHeader h)
        {
            if (!h.A4Counter.AsSpan().SequenceEqual(h.A5Counter))
                throw new InvalidOperationException("Manjuu counters differ — nonce-reuse attack not applicable for this bundle.");

            // keystream = AES(key, counter) = a5_ct XOR a5_pt = a5_ct XOR MagicVerify
            var keystream = new byte[16];
            for (int i = 0; i < 16; i++)
                keystream[i] = (byte)(h.A5Ciphertext[i] ^ MagicVerify[i]);

            // a4_pt = keystream XOR a4_ct
            var a4Pt = new byte[16];
            for (int i = 0; i < 16; i++)
                a4Pt[i] = (byte)(keystream[i] ^ h.A4Ciphertext[i]);

            Logger.Verbose($"[Manjuu] Keyless recovery: a4_pt={BitConverter.ToString(a4Pt).Replace("-","")}");
            return BuildPermTable(a4Pt);
        }

        /// <summary>
        /// Full AES-128-CTR decryption using the provided 16-byte key.
        /// Verifies a5 decrypts to "#$manjuuunity*!@", then decrypts a4.
        /// Returns (permTable[16], extraParams[16]).
        /// Throws if verification fails.
        /// </summary>
        public static (byte[] PermTable, byte[] ExtraParams) DecryptAndVerify(ManjuuHeader h, byte[] key)
        {
            if (key == null || key.Length != 16)
                throw new ArgumentException("Manjuu AES key must be exactly 16 bytes.");

            // Step 1: decrypt a5, verify magic
            var a5Pt = AesCtrDecrypt(key, h.A5Ciphertext, h.A5Counter);
            if (!a5Pt.AsSpan().SequenceEqual(MagicVerify))
                throw new InvalidDataException("Manjuu verification failed — wrong AES key.");

            // Step 2: decrypt a4, build perm table
            var a4Pt = AesCtrDecrypt(key, h.A4Ciphertext, h.A4Counter);
            Logger.Verbose($"[Manjuu] AES verify OK. a4_pt={BitConverter.ToString(a4Pt).Replace("-","")}");
            return BuildPermTable(a4Pt);
        }

        /// <summary>
        /// AES-128-CTR decrypt a single 16-byte block.
        /// counter is not modified; used only for one keystream block.
        /// </summary>
        public static byte[] AesCtrDecrypt(byte[] key, byte[] ciphertext, byte[] counter)
        {
            using var aes = Aes.Create();
            aes.Mode    = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key     = key;
            using var enc = aes.CreateEncryptor();

            var ks  = enc.TransformFinalBlock(counter, 0, 16);
            var pt  = new byte[ciphertext.Length];
            for (int i = 0; i < ciphertext.Length; i++)
                pt[i] = (byte)(ciphertext[i] ^ ks[i]);
            return pt;
        }

        /// <summary>
        /// AES-128-CTR decrypt an arbitrary-length buffer.
        /// Counter is incremented big-endian (byte[15] = LSB) for each 16-byte block.
        /// </summary>
        public static byte[] AesCtrDecryptMultiBlock(byte[] key, byte[] data, byte[] initialCounter)
        {
            using var aes = Aes.Create();
            aes.Mode    = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key     = key;
            using var enc = aes.CreateEncryptor();

            var result = new byte[data.Length];
            var ctr    = (byte[])initialCounter.Clone();

            for (int pos = 0; pos < data.Length; pos += 16)
            {
                var ks  = enc.TransformFinalBlock(ctr, 0, 16);
                var len = Math.Min(16, data.Length - pos);
                for (int i = 0; i < len; i++)
                    result[pos + i] = (byte)(data[pos + i] ^ ks[i]);

                // Increment counter big-endian (byte[15] = LSB)
                for (int i = 15; i >= 0; i--)
                {
                    ctr[i]++;
                    if (ctr[i] != 0) break;
                }
            }
            return result;
        }

        /// <summary>
        /// Decrypt the LZ4-compressed BlocksInfo using AES-128-CTR then decompress.
        /// counter: use the a4 counter (same value as a5 counter due to nonce reuse).
        /// </summary>
        public static byte[] DecryptBlocksInfo(ReadOnlySpan<byte> encrypted, int uncompressedSize, byte[] key, byte[] counter)
        {
            var decrypted = AesCtrDecryptMultiBlock(key, encrypted.ToArray(), counter);
            var uncompressed = new byte[uncompressedSize];
            var written = LZ4.Instance.Decompress(decrypted, uncompressed);
            if (written != uncompressedSize)
                throw new IOException($"[Manjuu] LZ4 decompression produced {written} bytes, expected {uncompressedSize}.");
            return uncompressed;
        }

        // Build permutation table and extra params from decrypted a4 plaintext.
        // Matches sub_1806A5400 output layout at a1[0..31]:
        //   a1[0..15]  = permTable  (perm_table[nibble] = position index)
        //   a1[16..31] = extraParams (column-interleaved nibbles of a4Pt[8..15])
        private static (byte[] PermTable, byte[] ExtraParams) BuildPermTable(byte[] a4Pt)
        {
            var perm = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                int byteVal = a4Pt[i >> 1];
                int nibble  = (i & 1) == 0 ? (byteVal >> 4) : (byteVal & 0xF);
                perm[nibble] = (byte)i;
            }

            var extra = new byte[16];
            extra[0]  = (byte)(a4Pt[8]  >> 4); extra[4]  = (byte)(a4Pt[8]  & 0xF);
            extra[8]  = (byte)(a4Pt[9]  >> 4); extra[12] = (byte)(a4Pt[9]  & 0xF);
            extra[1]  = (byte)(a4Pt[10] >> 4); extra[5]  = (byte)(a4Pt[10] & 0xF);
            extra[9]  = (byte)(a4Pt[11] >> 4); extra[13] = (byte)(a4Pt[11] & 0xF);
            extra[2]  = (byte)(a4Pt[12] >> 4); extra[6]  = (byte)(a4Pt[12] & 0xF);
            extra[10] = (byte)(a4Pt[13] >> 4); extra[14] = (byte)(a4Pt[13] & 0xF);
            extra[3]  = (byte)(a4Pt[14] >> 4); extra[7]  = (byte)(a4Pt[14] & 0xF);
            extra[11] = (byte)(a4Pt[15] >> 4); extra[15] = (byte)(a4Pt[15] & 0xF);

            return (perm, extra);
        }
    }
}
