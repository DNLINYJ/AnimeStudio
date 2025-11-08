using AnimeStudio.Crypto;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;


namespace AnimeStudio
{
    public class HYGFile
    {
        private List<BundleFile.StorageBlock> m_BlocksInfo;
        private List<BundleFile.Node> m_DirectoryInfo;
        private byte[] Header;

        public BundleFile.Header m_Header;
        public List<StreamFile> fileList;
        public long Offset;

        static readonly byte[] MAGIC7 = { 0xC3, 0x9C, 0xC3, 0xA3, 0xC3, 0x8A, 0x00 };

        struct Key16 { public ulong keyB; public ulong keyA_zext; }
        sealed class PreheaderParts { public Key16 Key; public byte[] EncHdr32 = new byte[32]; }
        sealed class DecodedFields
        {
            public ulong blkSize;            // dec[0..7]
            public uint compressionSize;    // dec[8..11]
            public uint uncompressionSize;  // dec[12..15]
            public uint flag;               // dec[16..19] & 0x3F
            public byte[] hash8 = Array.Empty<byte>(); // dec[24..31]
        }
        static DecodedFields ParseDecodedFields(byte[] dec) => new DecodedFields
        {
            blkSize = BitConverter.ToUInt64(dec, 0),
            compressionSize = BitConverter.ToUInt32(dec, 8),
            uncompressionSize = BitConverter.ToUInt32(dec, 12),
            flag = BitConverter.ToUInt32(dec, 16),
            hash8 = dec.Skip(24).Take(8).ToArray()
        };

        // —— 就地预解码（封装 CryptoUtils.DecryptHeaderInPlace 的 32B 变体到任意长度）——
        static bool PredecodeInPlace(byte[] src, uint dstCap, uint srcLen)
        {
            if (srcLen > (uint)src.Length) return false;
            var span = src.AsSpan(0, (int)srcLen);
            ulong keyB = dstCap;  // 目标容量
            ulong keyA = srcLen;  // 源长度
            return HYGUtils.PredecodeInPlace(span, keyB, keyA); // ← 用新增的任意长度版
        }

        public HYGFile(FileReader reader, string path)
        {
            // normal HYG init
            HYGUtils.Init();

            Offset = reader.Position;

            var magic = reader.ReadBytes(7);
            bool hasMagic = magic.AsSpan().SequenceEqual(MAGIC7);
            if (!hasMagic) // HYG 文件头
                throw new Exception("not a HYG file");

            reader.Endian = EndianType.BigEndian;
            uint keyA = reader.ReadUInt32();
            ulong keyB = reader.ReadUInt64();
            reader.Endian = EndianType.LittleEndian;

            byte[] encHeader = reader.ReadBytes(32);
            reader.AlignStream(16); // 16 字节对齐

            PreheaderParts s_encHeader = new PreheaderParts { Key = new Key16 { keyB = keyB, keyA_zext = keyA }, EncHdr32 = encHeader };
            var decHeader = HYGUtils.DecryptHeader(s_encHeader.EncHdr32, s_encHeader.Key.keyB, s_encHeader.Key.keyA_zext);
            var d_Header = ParseDecodedFields(decHeader);

            m_Header = new BundleFile.Header
            {
                version = 5,
                unityVersion = "5.x.x",
                unityRevision = "2022.3.43f1",
            };
            m_Header.compressedBlocksInfoSize = d_Header.compressionSize;
            m_Header.uncompressedBlocksInfoSize = d_Header.uncompressionSize;
            m_Header.flags = (ArchiveFlags)d_Header.flag;

            Logger.Verbose($"Header: {m_Header}");

            ReadBlocksInfoAndDirectory(reader);
            using var blocksStream = CreateBlocksStream(path);
            ReadBlocks(reader, blocksStream);
            ReadFiles(blocksStream, path);
        }

        private void ReadBlocksInfoAndDirectory(FileReader reader)
        {
            // 解密 BlocksInfo
            var blocksInfoBytes = reader.ReadBytes((int)m_Header.compressedBlocksInfoSize);
            reader.AlignStream(16);
            PredecodeInPlace(blocksInfoBytes, m_Header.uncompressedBlocksInfoSize, m_Header.compressedBlocksInfoSize);

            MemoryStream blocksInfoUncompresseddStream;
            var blocksInfoBytesSpan = blocksInfoBytes.AsSpan(0, (int)m_Header.compressedBlocksInfoSize);
            var uncompressedSize = m_Header.uncompressedBlocksInfoSize;

            var uncompressedBytes = ArrayPool<byte>.Shared.Rent((int)uncompressedSize);
            try
            {
                var uncompressedBytesSpan = uncompressedBytes.AsSpan(0, (int)uncompressedSize);
                var numWrite = LZ4.Instance.Decompress(blocksInfoBytesSpan, uncompressedBytesSpan);
                if (numWrite != uncompressedSize)
                {
                    throw new IOException($"Lz4 decompression error, write {numWrite} bytes but expected {uncompressedSize} bytes");
                }
                blocksInfoUncompresseddStream = new MemoryStream(uncompressedBytesSpan.ToArray());
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(uncompressedBytes, true);
            }

            using (var blocksInfoReader = new EndianBinaryReader(blocksInfoUncompresseddStream))
            {
                var uncompressedDataHash = blocksInfoReader.ReadBytes(16);

                var blocksInfoCount = blocksInfoReader.ReadInt32();
                m_BlocksInfo = new List<BundleFile.StorageBlock>();
                Logger.Verbose($"Blocks count: {blocksInfoCount}");
                for (int i = 0; i < blocksInfoCount; i++)
                {
                    m_BlocksInfo.Add(new BundleFile.StorageBlock
                    {
                        uncompressedSize = blocksInfoReader.ReadUInt32(),
                        compressedSize = blocksInfoReader.ReadUInt32(),
                        flags = (StorageBlockFlags)blocksInfoReader.ReadUInt16()
                    });

                    Logger.Verbose($"Block {i} Info: {m_BlocksInfo[i]}");
                }

                var nodesCount = blocksInfoReader.ReadInt32();
                m_DirectoryInfo = new List<BundleFile.Node>();
                Logger.Verbose($"Directory count: {nodesCount}");
                for (int i = 0; i < nodesCount; i++)
                {
                    m_DirectoryInfo.Add(new BundleFile.Node
                    {
                        offset = blocksInfoReader.ReadInt64(),
                        size = blocksInfoReader.ReadInt64(),
                        flags = blocksInfoReader.ReadUInt32(),
                        path = blocksInfoReader.ReadStringToNull(),
                    });

                    Logger.Verbose($"Directory {i} Info: {m_DirectoryInfo[i]}");
                }
            }
        }

        private Stream CreateBlocksStream(string path)
        {
            Stream blocksStream;
            var uncompressedSizeSum = (int)m_BlocksInfo.Sum(x => x.uncompressedSize);
            Logger.Verbose($"Total size of decompressed blocks: 0x{uncompressedSizeSum:X8}");
            if (uncompressedSizeSum >= int.MaxValue)
                blocksStream = new FileStream(path + ".temp", FileMode.Create, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose);
            else
                blocksStream = new MemoryStream(uncompressedSizeSum);
            return blocksStream;
        }

        private void ReadBlocks(FileReader reader, Stream blocksStream)
        {
            foreach (var blockInfo in m_BlocksInfo)
            {
                var compressionType = (CompressionType)(blockInfo.flags & StorageBlockFlags.CompressionTypeMask);
                Logger.Verbose($"Block compression type {compressionType}");
                switch (compressionType) //kStorageBlockCompressionTypeMask
                {
                    case CompressionType.None: //None
                        {
                            reader.BaseStream.CopyTo(blocksStream, blockInfo.compressedSize);
                            break;
                        }
                    case CompressionType.Lz4:
                    case CompressionType.Lz4HC:
                    case CompressionType.Lz4HYG:
                        {
                            var compressedSize = (int)blockInfo.compressedSize;
                            var uncompressedSize = (int)blockInfo.uncompressedSize;

                            var compressedBytes = ArrayPool<byte>.Shared.Rent(compressedSize);
                            var uncompressedBytes = ArrayPool<byte>.Shared.Rent(uncompressedSize);

                            var compressedBytesSpan = compressedBytes.AsSpan(0, compressedSize);
                            var uncompressedBytesSpan = uncompressedBytes.AsSpan(0, uncompressedSize);

                            try
                            {
                                reader.Read(compressedBytesSpan);
                                if (compressionType == CompressionType.Lz4HYG)
                                    PredecodeInPlace(compressedBytes, (uint)uncompressedSize, (uint)compressedSize);

                                var numWrite = LZ4.Instance.Decompress(compressedBytesSpan, uncompressedBytesSpan);
                                if (numWrite != uncompressedSize)
                                {
                                    Logger.Warning($"Lz4 decompression error, write {numWrite} bytes but expected {uncompressedSize} bytes");
                                }
                            }
                            catch (Exception e)
                            {
                                Logger.Error($"Lz4 decompression error {e.Message}");
                            }
                            finally
                            {
                                blocksStream.Write(uncompressedBytesSpan);
                                ArrayPool<byte>.Shared.Return(compressedBytes, true);
                                ArrayPool<byte>.Shared.Return(uncompressedBytes, true);
                            }
                            break;
                        }
                    default:
                        throw new IOException($"Unsupported compression type {compressionType}");
                }
            }
        }

        private void ReadFiles(Stream blocksStream, string path)
        {
            Logger.Verbose($"Writing files from blocks stream...");

            fileList = new List<StreamFile>();
            for (int i = 0; i < m_DirectoryInfo.Count; i++)
            {
                var node = m_DirectoryInfo[i];
                var file = new StreamFile();
                fileList.Add(file);
                file.path = node.path;
                file.fileName = Path.GetFileName(node.path);
                if (node.size >= int.MaxValue)
                {
                    var extractPath = path + "_unpacked" + Path.DirectorySeparatorChar;
                    Directory.CreateDirectory(extractPath);
                    file.stream = new FileStream(extractPath + file.fileName, FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite);
                }
                else
                    file.stream = new MemoryStream((int)node.size);
                blocksStream.Position = node.offset;
                blocksStream.CopyTo(file.stream, node.size);
                file.stream.Position = 0;
            }
        }
    }
}
