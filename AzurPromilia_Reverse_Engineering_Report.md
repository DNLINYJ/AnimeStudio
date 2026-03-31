# AzurPromilia (蓝色星原：旅谣) CB2 资产包解密逆向分析报告

**目标游戏**：AzurPromilia（蓝色星原：旅谣）封闭测试 2（CB2）
**平台**：PC（Windows）
**引擎**：Unity 2022.3.62f3（IL2CPP 后端）
**分析日期**：2026-03-31

---

## 1. 概述

AzurPromilia CB2 的资产包（AssetBundle）基于标准 UnityFS 格式，并在其之上叠加了由 Manjuu 自研的额外加密层。该加密层通过在包头写入额外的 70 字节密文块来传递数据块解密所需的置换表；数据块本身使用与 UnityCN 相同的半字节（nibble）替换算法进行加密。

本报告完整记录从零开始找到加密密钥、分析加密算法结构、最终在 AnimeStudio 中实现完整解密管线的全过程。

---

## 2. 工具与环境

| 工具 | 用途 |
|------|------|
| IDA Pro + ida-pro-mcp | 静态反编译 `UnityPlayer.dll`（MCP 端口 13337）|
| IDA Pro + ida-pro-mcp | 静态反编译 `GameAssembly.dll`（MCP 端口 13338）|
| il2cppdumper | 生成 IL2CPP Dump（`dump.cs`、`script.json`、`stringliteral.json`）|
| Python | 二进制验证脚本 |
| AnimeStudio（C#）| 最终解密实现 |

IL2CPP Dump 结果位于：`F:\解密记录\蓝源二测\AzurPromilia_Game\DumpResult\`

---

## 3. 逆向过程

### 3.1 定位 AES 密钥（IL2CPP Dump 分析）

**第一步：在 `dump.cs` 中寻找资产加载入口**

`il2cppdumper` 生成的 `dump.cs` 包含完整的 IL2CPP 类型与方法声明。搜索 `YooAsset`（游戏使用的资产管理框架）得到：

```
// RVA: 0x982C460
static void YooAssets::Initialize(...)
```

**第二步：交叉验证 `script.json`**

`script.json` 中记录了方法地址到名称的映射，确认：

```json
{ "Address": "0x18982C460", "Name": "YooAsset.YooAssets$Initialize" }
```

**第三步：GameAssembly.dll 反编译**

通过 IDA Pro MCP 对 `sub_18982C460` 进行反编译，观察到其调用链：

```c
sub_18982C460(...)
  └─ sub_1893CD610(qword_18C3C8088)   // SetAssetBundleDecryptKey 的 IL2CPP 包装
```

`sub_1893CD610` 为 `SetAssetBundleDecryptKey` 的 IL2CPP 桩函数，接受一个 `Il2CppString*` 参数，即密钥字符串。参数来源为全局指针 `qword_18C3C8088`。

**第四步：在 `stringliteral.json` 中还原字符串**

`qword_18C3C8088` 对应的 RVA 为 `0xC3C8088`，在 `stringliteral.json` 中按地址查找：

```json
{ "index": 42510, "address": "0xC3C8088", "value": "z4l23bh5#35h&321" }
```

**AES 密钥确认**：

```
z4l23bh5#35h&321
```

十六进制表示：`7A346C32336268352333356826333231`（16 字节，AES-128）

**第五步：UnityPlayer.dll 验证密钥用途**

通过 IDA Pro MCP 分析 `sub_1801CC6B0`（`SetAssetBundleDecryptKey`），确认其将密钥字符串存储至全局指针 `qword_181C1E8C0 + 40`，供后续 `ReadBlocksInfo`（`sub_1806995C0`）读取并执行 AES 解密。

---

### 3.2 Bundle 格式分析（UnityPlayer.dll）

**涉及的关键函数地址（UnityPlayer.dll）**：

| 地址 | 函数 | 说明 |
|------|------|------|
| `0x1806995C0` | `ReadBlocksInfo` | 读取 Manjuu 头部，构建置换表，读取并解压 BlocksInfo |
| `0x1806A5400` | `BuildPermTable` | 从 a4/a5 块构建置换表至 `a1+2868` |
| `0x1806964E0` | `AlignedHeaderSize` | 返回 `(header_end + 15) & ~0xF`（version >= 7 时生效）|
| `0x1801CC6B0` | `SetAssetBundleDecryptKey` | 将密钥存入 `qword_181C1E8C0 + 40` |

通过对 `ReadBlocksInfo` 的反编译分析，归纳出完整的包头布局（以测试样本为例，`flags = 0x643`）。

---

## 4. 加密方案详解

### 4.1 Bundle 文件整体布局

标准 UnityFS 头部字段读取完毕后（至偏移 `0x2C`），若 `flags & 0x400 != 0`，则紧随其后是 Manjuu 自定义加密头部，共 **70 字节**：

```
偏移    大小    字段
0x2C    4       extra_field (u32 大端)
0x30    16      a4_ciphertext
0x40    16      a4_counter (AES-CTR IV)
0x50    1       null terminator
0x51    16      a5_ciphertext
0x61    16      a5_counter (AES-CTR IV)
0x71    1       null terminator
```

读完 Manjuu 头部后偏移为 `0x72`。
随后执行 `AlignStream(16)` → 偏移对齐至 **`0x80`**，BlocksInfo 从此处开始。

### 4.2 flags 字段语义

样本中 `flags = 0x643`，各位含义如下：

| 位掩码 | 值 | 含义 |
|--------|----|------|
| `0x3F` | `0x03` | LZ4 压缩 |
| `0x40` | 置位 | BlocksAndDirectoryInfoCombined |
| `0x200` | 置位 | BlockInfoNeedPaddingAtStart（BlocksInfo 后再次对齐）|
| `0x400` | 置位 | Manjuu 加密头部存在 |

### 4.3 各组件加密状态

| 组件 | 加密状态 | 方法 |
|------|----------|------|
| Manjuu 头部（a4/a5 块）| **已加密** | AES-128-CTR，密钥 = 游戏 AES 密钥 |
| BlocksInfo | **未加密** | 直接 LZ4，从对齐后偏移 `0x80` 读取 |
| 数据块（flag `0x100`）| **已加密** | UnityCN 风格的半字节替换（nibble substitution）|

> **重要结论**：BlocksInfo **不加密**，之前尝试对其进行 AES-CTR 解密是错误的，直接在对齐后地址（`0x80`）做 LZ4 解压即可。

### 4.4 Manjuu 头部解密原理（AES-128-CTR）

a4 和 a5 各自是一个使用 AES-128-CTR 加密的 16 字节块：

- `a5` 的明文为已知常量：`#$manjuuunity*!@`（用于验证密钥正确性）
- `a4` 的明文编码了数据块解密所需的**置换表**（PermTable）和**额外参数**（ExtraParams）

解密过程：

```
keystream_block = AES_ECB_Encrypt(key, counter)
plaintext       = ciphertext XOR keystream_block
```

### 4.5 Nonce 重用漏洞（Keyless Recovery）

**关键发现**：在所有观察到的 CB2 样本中，`a4_counter == a5_counter`（计数器完全相同，即 Nonce 重用）。

这意味着 a4 和 a5 使用了**相同的 AES-CTR 密钥流块**，可在完全不知道 AES 密钥的情况下还原 a4 明文：

```python
# a5 已知明文（magic）
magic     = b"#$manjuuunity*!@"

# 用 a5 还原密钥流
keystream = bytes(a ^ b for a, b in zip(a5_ciphertext, magic))

# 用密钥流还原 a4 明文
a4_pt     = bytes(a ^ b for a, b in zip(a4_ciphertext, keystream))
```

**所有 CB2 样本的共同 a4 明文**：`0123456789abcdef2c4a582385331236`

这直接导致：所有 CB2 包的置换表完全一致：
- **PermTable（Index）**：`[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]`（恒等置换）
- **ExtraParams（Sub）**：`[2,5,8,1,12,8,5,2,4,2,3,3,10,3,3,6]`

### 4.6 置换表构建算法（BuildPermTable）

还原自 `sub_1806A5400`，从 a4 明文的 16 字节构建 `PermTable[16]` 和 `ExtraParams[16]`：

```python
# PermTable: 按每个 nibble 建立逆映射
perm = [0] * 16
for i in range(16):
    byte_val = a4_pt[i >> 1]
    nibble   = (byte_val >> 4) if (i & 1 == 0) else (byte_val & 0xF)
    perm[nibble] = i

# ExtraParams: 列交错读取 a4_pt[8..15] 的 nibble
# extra[col*4 + row] = nibble(a4_pt[8 + col*2 + row//2], row%2==0 ? high : low)
```

### 4.7 数据块解密（UnityCN 半字节替换）

数据块在存储时以 LZ4 **压缩后**的格式进行加密（即先加密，后解压）。算法与 UnityCN 完全相同，按 LZ4 token 结构感知式替换：

对每个 LZ4 token 字节，解密公式为：
```
b_val  = Sub[((idx>>2)&3)+4] + Sub[idx&3] + Sub[((idx>>4)&3)+8] + Sub[(idx>>6)+12]
high   = (Index[original >> 4] - b_val) & 0xF
low    = (Index[original & 0xF] - b_val) & 0xF
result = (high << 4) | low
```

算法按 LZ4 格式感知地跳过字面量字节，仅解密 token、match offset 和长度扩展字节。

---

## 5. 实现

### 5.1 新增文件：`AnimeStudio/Crypto/ManjuuUtils.cs`

封装 Manjuu 头部读取、keyless 恢复、AES-CTR 解密、置换表构建：

```csharp
public class ManjuuHeader {
    public uint   ExtraField;
    public byte[] A4Ciphertext, A4Counter;
    public byte[] A5Ciphertext, A5Counter;
}

public static class ManjuuUtils {
    // 读取 70 字节 Manjuu 头部
    public static ManjuuHeader ReadHeader(EndianBinaryReader reader);

    // Keyless Nonce 重用攻击（无需 AES 密钥）
    public static (byte[] PermTable, byte[] ExtraParams) RecoverKeyless(ManjuuHeader h);

    // 完整 AES-128-CTR 解密 + 验证（需要密钥）
    public static (byte[] PermTable, byte[] ExtraParams) DecryptAndVerify(ManjuuHeader h, byte[] key);
}
```

### 5.2 `AnimeStudio/Crypto/UnityCN.cs`

新增接受预计算表的构造函数，供 Manjuu keyless 路径直接使用：

```csharp
/// <summary>Pre-computed tables constructor (for Manjuu / keyless recovery).</summary>
public UnityCN(byte[] index, byte[] sub)
{
    index.CopyTo(Index, 0);
    sub.CopyTo(Sub, 0);
}
```

### 5.3 `AnimeStudio/BundleFile.cs`

**修改 1：移除对齐跳过条件**

原代码的 `if (version >= 7 && !Game.Type.IsAzurPromilia())` 会在 AzurPromilia 下跳过 `AlignStream(16)`，导致 BlocksInfo 从错误偏移（`0x72`）读取。修正为：

```csharp
if (m_Header.version >= 7 && !Game.Type.IsSRGroup())
{
    reader.AlignStream(16);
}
```

**修改 2：删除错误的 BlocksInfo AES-CTR 解密**

BlocksInfo 为纯 LZ4 数据，之前对其进行 AES-CTR 解密是错误的，该代码块已完全删除。

**修改 3：`ReadManjuu` 方法**

读取 Manjuu 头部，优先尝试 keyless 恢复，失败时回退到密钥解密：

```csharp
private void ReadManjuu(FileReader reader)
{
    if ((m_Header.flags & ArchiveFlags.UnityCNEncryption) == 0) return;
    m_ManjuuHeader = ManjuuUtils.ReadHeader(reader);

    byte[] perm = null, extra = null;
    try   { (perm, extra) = ManjuuUtils.RecoverKeyless(m_ManjuuHeader); }
    catch { /* nonce reuse not applicable */ }

    if (perm == null && Game is ManjuuGame g && g.HasKey)
        (perm, extra) = ManjuuUtils.DecryptAndVerify(m_ManjuuHeader, g.Key);

    if (perm != null) UnityCN = new UnityCN(perm, extra);
}
```

**修改 4：`ReadBlocks` 中的数据块解密**

```csharp
if (Game.Type.IsAzurPromilia() && ((int)blockInfo.flags & 0x100) != 0 && UnityCN != null)
{
    UnityCN.DecryptBlock(compressedBytes, compressedSize, i);
}
```

### 5.4 `AnimeStudio/GameManager.cs`

新增 `ManjuuGame` 类型及 AzurPromilia CB2 游戏项：

```csharp
public record ManjuuGame : Game
{
    public byte[] Key { get; private set; }
    public bool HasKey => Key != null && Key.Length == 16;
    // ...
}

Games.Add(index++, new ManjuuGame(GameType.AzurPromilia_CB2, "AzurPromilia CB2"));
```

### 5.5 `AnimeStudio/AssetsManager.cs`

CB2 的 SerializedFile 中 Unity 版本字段被剥除（stripped）。修改 `CheckStrippedVersion` 自动回填版本号：

```csharp
public void CheckStrippedVersion(SerializedFile assetsFile)
{
    var effectiveVersion = SpecifyUnityVersion;
    if (string.IsNullOrEmpty(effectiveVersion) && Game?.Type.IsAzurPromilia() == true)
        effectiveVersion = "2022.3.62f3";
    if (assetsFile.IsVersionStripped && string.IsNullOrEmpty(effectiveVersion))
        throw new Exception("The Unity version has been stripped, please set the version in the options");
    if (!string.IsNullOrEmpty(effectiveVersion))
        assetsFile.SetVersion(effectiveVersion);
}
```

---

## 6. 解密验证

使用测试包（`StreamingAssets/.res/default_package/00jzcmlpxh3dvj8jge4hha`）全程验证：

**包头字段**（偏移 `0x00`–`0x2B`）：
```
signature:             UnityFS
version:               9
unityVersion:          0.0.0
unityRevision:         2022.3.62f3
size:                  0x(...)
compressedBlocksInfo:  65 bytes
uncompressedBlocksInfo: 91 bytes
flags:                 0x643
```

**Manjuu 头部**（`0x2C`–`0x71`）：
```
extra_field:   (4 bytes)
a4_ct:         (16 bytes)
a4_ctr:        (16 bytes)
a5_ct:         (16 bytes)
a5_ctr:        (16 bytes)  ← 与 a4_ctr 完全相同 → Nonce 重用成立
```

**Keyless 恢复验证**：
```python
keystream = a5_ct XOR b"#$manjuuunity*!@"
a4_pt     = a4_ct XOR keystream
# → 0123456789abcdef2c4a582385331236

# AES-ECB 验证（有密钥时）：
AES.ECB.Encrypt("z4l23bh5#35h&321", a5_counter) XOR a5_ct == b"#$manjuuunity*!@"  ✓
```

**BlocksInfo**（偏移 `0x80`，65 字节 LZ4）：
```
直接 LZ4 解压 → 91 字节 ✓
包含 1 个 StorageBlock: compressedSize=0xDBB8, uncompressedSize=0xDBB8, flags=0x103
```

**数据块**（`flags=0x103`：LZ4 + nibble 加密）：
```
UnityCN.DecryptBlock(compressedBytes, compressedSize=0xDBB8, blockIndex=0)
LZ4.Decompress → uncompressedSize=0xDBB8 字节
写入 SerializedFile 流，正常解析资产 ✓
```

---

## 7. 结论

| 问题 | 根因 | 修复方案 |
|------|------|----------|
| BlocksInfo 读取偏移错误 | `AlignStream(16)` 被 `IsAzurPromilia()` 条件跳过 | 移除该条件 |
| BlocksInfo 解密失败 | 错误地对纯 LZ4 数据进行 AES-CTR 解密 | 删除该解密块 |
| 数据块未解密 | 未对 flag `0x100` 的 LZ4 块执行 nibble 替换 | 添加 UnityCN 解密调用 |
| Unity 版本 stripped | SerializedFile 内嵌版本被剥除 | 自动回填 `2022.3.62f3` |
| Keyless 恢复 | AES 密钥非必须——Nonce 重用即可还原置换表 | 优先 keyless，降级到密钥路径 |

Manjuu 的加密设计引入了两处根本性弱点：
1. **Nonce 重用**：a4 与 a5 共用同一 AES-CTR 计数器，使得无需密钥即可还原 a4 明文。
2. **固定置换表**：CB2 阶段全部包共用同一 a4 明文，UnityCN 的 nibble 替换因此具有相同的密钥参数。
