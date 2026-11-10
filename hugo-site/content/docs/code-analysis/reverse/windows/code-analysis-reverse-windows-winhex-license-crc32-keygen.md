---
id: code-analysis-reverse-windows-winhex-license-crc32-keygen
title: WinHex 21.3 SR-8 x86 注册算法逆向与 Keygen：CRC32 校验、DOS 日期/用户数编码与 Delphi license 结构
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: winhex-delphi-license-struct-crc32-dosdate-keygen
tags:
- reverse
- windows
- delphi
- license
- keygen
- crc32
- dosdate
- x64dbg
- anti-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V270
  verified_at: '2026-11-07T19:53:35+08:00'
  notes: 已对照原文与全部25张图核对：license 六行格式（Name/Addr×2/Key×2/Cksm）、0xEB 块 + 'sector-aligned' 的 CRC32（poly 0xEDB88320，运行时生成查表）、Key1 结构、off_62C4AC=(b8^bC^0xB7)>>5 的 2=个人/3=专业、word_648EC0/word_648EC2/word_648EC8 三个字段的公式与 DOS 日期编码、wFatDate 演示版覆盖、sub_5D85D0 取系统时间/2024-10-26/google.de/C:\windows 最新写入时间四者最大值、off_62B918 指针反 xref，均与原文及图03-07、10-25一致；keygen C 代码与原文逐段对应。原文为单机逆向案例，无 CVE/组件版本，affected_versions 保持 null。dedup：唯一 exact 为自身；与同文 Delphi 对话框定位卡为互补关系（一为输入定位、一为算法/Keygen），候选 crc32 XOR/API hash 等均不同场景；dup-scan 无本篇 pair。未验证点：keygen 未编译复跑，授权结果以原文截图为准。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-winhex-license-crc32-keygen/
draft: false
kb_aliases:
- WinHex 21.3 Keygen
- WinHex 注册码分析
- WinHex license 格式
- Cksm CRC32
- sector-aligned
- word_648EC0
- word_648EC2
- word_648EC8
- off_62C4AC
- Delphi 注册算法逆向
---

## 一句话结论

WinHex 21.3 SR-8 x86（Delphi 程序，未加壳）的 license 是一段固定字段文本：`Name`、两个 `Addr`、两个 16 字节 `Key`（或 `Data`）和 `Cksm`。程序把前三个字符串与两个 16 字节散列拼成 0xEB 字节块，追加常量 `"sector-aligned"` 后计算标准 CRC32（多项式 0xEDB88320，运行时生成查表以隐藏特征），结果与 `Cksm` 比较；第一个 16 字节 Key 的结构里还编码了授权类型（个人/专业）、可用截止日期、可升级截止日期和最大协作用户数。按这些字段关系构造 Key 并计算 CRC32，即可生成通过首次校验并在重启后生效的 license。

## 原理

- **license 文本格式**：首次注册时对话框读入一段多行文本，字段为 `Name:`、`Addr:`（两项）、`Key:`（两项，或 `Data:`）与 `Cksm:`。调试可确认 `Name`/`Addr` 只是普通字符串，license 内部按 0x51、0x3D、0x3D 字节的固定槽位存放并补零；两个 Key 各 16 字节，由 `%02X` 文本解析回二进制。
- **CRC32 校验**：`sub_5C943C` 的 Cksm 分支先调用 `sub_416C44` 初始化 CRC32 查找表（参数 6，反向多项式 0xEDB88320），再对 0xEB 字节块（Name/Addr/Addr + 32 字节 Key）和 14 字节字符串 `"sector-aligned"` 分两段更新 CRC，最后 `sub_4171D8` 做 XOR 0xFFFFFFFF 收尾，与解析出的 `Cksm` 比较。查表在运行时生成，静态分析看不到典型 CRC 常数表，是不易识别的保护手法。
- **Key1 结构**：16 字节可视为 `{word w0; word w2; word w4; word w6; byte b8; byte b9; word wA; union {word wC; struct {byte bC; byte bD;}}; word wE;}`。程序把 `Key`/`Data` 文本转换后写入 `byte_648BD3` 起的两块 16 字节区域，后续所有校验围绕第一块。
- **授权类型**：`off_62C4AC` 指向的字节等于 `(b8 ^ bC ^ 0xB7) >> 5`；值为 2 表示个人授权，3 表示专业授权。`bD` 的低 5 位参与入口分支选择，`bD = 0x15` 走 Key 路径并使 `byte_648C88 == 0x15`。
- **日期/用户数字段**（与 keygen 代码一致）：
  - `word_648EC0 = ((w4 ^ w6 ^ 0x159D) & 0x3FFF) + 0x4705`，按 DOS 日期编码（`year = (v>>9)+1980`、`month = (v>>5)&0xF`、`day = v&0x1F`），代表授权/升级截止日期；其原始值的最高两位决定 `word_648EC2` 与 `wFatDate` 的赋值组合。
  - `word_648EC2 = ((wC ^ w2 ^ 0xEA69) & 0x3FFF) + 0x4705`，代表“可免费升级”的截止日期；赋值且不晚于当前时间时，`sub_441C9C` 授权时间校验才会被跳过。
  - `word_648EC8 = w2 ^ wA ^ 0x69C5`，必须 ≤ 0xEA6（3750），代表最大协作用户数。
  - `wFatDate` 是演示版（evaluation）截止日期，赋值时界面显示 “For evaluation purposes only! Not for sale.” 且不可升级。
- **可用的授权组合**：文章测试发现，只有 `word_648EC2` 被赋值而 `wFatDate` 不被赋值时，才是可免费升级、不弹“使用期已过”且能正常使用的授权；`wFatDate` 赋值会覆盖 `word_648EC2`，进入演示模式。keygen 通过选择 `word_648EC0` 原始值的最高两位构造该组合。
- **防止改系统时间**：真正的日期校验函数 `sub_5D85D0` 取四者最大值——当前系统时间、构建常量 2024-10-26、`google.de` 网络返回日期、`C:\windows` 目录下最近写入文件的日期。把系统时间调早无法绕过；这也是断网环境下启动极慢的原因。
- **反 xref 手法**：`word_648EC2` 的赋值、校验与结果展示分散在三处，且校验处通过指针 `off_62B918` 间接引用变量，静态交叉引用只能看到读指针，找不到变量本身的写入点；需要硬件断点或逐个检查指针引用才能串起来。

## 触发条件

- 目标为 WinHex 21.3 SR-8 x86（Delphi、无壳），且拥有可输入 license 的注册对话框。
- 分析者能在本机运行并用 x64dbg 附加调试；能读取/修改 `user.txt` 或直接构造 license 文本。
- 已知 license 字段布局与 CRC32 参数；目标未对调试、内存修改做额外强保护（文章未遇到壳/反调试）。
- 生成 license 的日期字段需满足相对当前日期的时间约束（`word_648EC2` 不晚于当前本地日期）。

## 利用步骤

1. 运行程序，在 `DialogBoxParamW` 下断，定位注册对话框与消息回调（第 4 个参数），用 Resource Hacker 查对话框 ID=0x2C 及 EDIT 控件 ID（0x30A/0x30B/0x66）。
2. 在 `GetDlgItem` 上以 `[esp+8] == 0x30A` 条件断点定位 license 输入读取，跟进 `GetWindowTextA` 后的 `sub_5C943C`。
3. 跟踪 `sub_5C943C`，识别 `Name:`/`Addr:`/`Key:`/`Data:`/`Cksm:` 字段与 16 字节散列解析，记录 0xEB 块布局与 `"sector-aligned"` 常量。
4. 定位 Cksm CRC32：`sub_416C44` 初始化查表、`sub_416EC4` 分段更新、`sub_4171D8` 取反收尾；确认多项式 0xEDB88320。
5. 跟踪 `word_648EC0`/`word_648EC2`/`word_648EC8`/`off_62C4AC` 的赋值与校验分支，推导出日期、用户数、授权类型与 Key 字节的线性关系。
6. 重启后校验读取 `user.txt`，在 `CreateFileW` 上断点定位 `sub_5C943C` 的文件分支；结合授权成功/失败对话框回溯，确认 `word_648EC2` 与 `wFatDate` 的赋值组合对授权模式的影响。
7. 按 keygen 逻辑生成随机 Key1/Key2，设置 `bD=0x15`、按个人授权反推 `bC`、按目标日期反推 `w2`/`w6`、按用户数反推 `wA`，最后计算并输出 `Cksm`。
8. 将生成的 6 行 license 粘贴到注册对话框，重启验证授权状态与“关于”界面。

## PoC

文章给出的 Keygen 核心（完整代码见原文，需 OpenSSL `RAND_bytes`）：

```c
typedef struct {
    word w0, w2, w4, w6;
    byte b8, b9;
    word wA;
    union { word wC; struct { byte bC, bD; }; };
    word wE;
} KEY1;

char *pname = license_block;
char *paddr1 = pname + 0x51;
char *paddr2 = paddr1 + 0x3D;
KEY1 *pkey1 = (KEY1 *)(paddr2 + 0x3D);
unsigned char *pkey2 = (unsigned char *)(pkey1 + 1);
char *ptail = (char *)(pkey2 + 16);
strncpy(ptail, "sector-aligned", 14);

generate_random_hash(pkey1, 16);       // Key1 随机且字节非零
generate_random_hash(pkey2, 16);       // Key2 随机
pkey1->bD = 0x15;                      // 走 Key 路径，byte_648C88 = 0x15

// 个人授权：[off_62C4AC] = (b8 ^ bC ^ 0xB7) >> 5 = 2
pkey1->bC = pkey1->b8 ^ 0xB7 ^ (2 << 5);
if (pkey1->bC == 0) pkey1->bC++;

// word_648EC2 = 2024-10-26 (0x595A)
pkey1->w2 = ((0x595A - 0x4705) & 0x3FFF) ^ 0xEA69 ^ pkey1->wC;

// word_648EC8 = 512 (最大协作用户数)
pkey1->wA = 0x200 ^ 0x69C5 ^ pkey1->w2;

// word_648EC0 = 2026-10-01 (0x5D41)，最高两位选 00 组合
pkey1->w6 = ((0x5D41 - 0x4705) & 0x3FFF) ^ 0x159D ^ pkey1->w4;

// CRC32 覆盖 license_block[0..0xEB] + "sector-aligned" 14 字节
generate_crc32_table();
unsigned int cksm = crc32_using_table(license_block, sizeof(license_block));
```

CRC32 参数：

```c
POLY = 0xEDB88320;
crc = 0xFFFFFFFF;
for each byte b: crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF];
final = crc ^ 0xFFFFFFFF;   // 按内存字节序输出（x86 小端）：CRC32=0x649A6A71 时文本为 716A9A64
```

生成后 license 示例格式：

```text
Name: snake
Addr: 888 Street
Addr: Lost Temper
Key: BEEF56ED3412331D8CDD358A6A15DEAD
Key: 07070707070707070707070707070707
Cksm: 716A9A64
```

## 变体与关联

- 授权类型变体：将 `(2 << 5)` 改为 `(3 << 5)` 可构造专业授权；`off_62C4AC` 的取值同时受 `bC`/`b8` 约束，改动后需重算 `Cksm`。
- 时间字段变体：`word_648EC0`（截止日期）与 `word_648EC2`（可升级截止日期）都按 DOS 日期编码；调整日期后要同步修改 `w2`/`w6` 并重算 CRC32。
- 入口变体：`Data:` 路径与 `Key:` 路径共用后续校验，但入口字节换算不同；文章主要分析 Key 路径。
- 保护绕过变体：若只 NOP 首次校验，重启后仍会校验 `user.txt`；需要同时满足 `word_648EC2`/`wFatDate` 组合与 CRC32。
- 关联：[`code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint`](code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint.md)（另一类桌面软件注册码定位）、[`code-analysis-dynamic-debugging-crackme-password-check-patch`](code-analysis-dynamic-debugging-crackme-password-check-patch.md)（动态改寄存器/ZF 绕过校验）、[`ctf-reverse-aes-mixcolumns-extra-xor-0x55`](ctf-reverse-aes-mixcolumns-extra-xor-0x55.md)（魔改算法写注册机）。

## 检测与防御

- 软件保护方：不要只用单一 CRC32 校验整块 license；对关键字段做非线性的签名/HMAC，且把校验结果分散到多点交叉验证。
- 避免把授权类型、日期、用户数简单编码进可逆的固定偏移字段；使用服务器端激活或非对称签名，避免本地可离线伪造。
- 时间校验不要只读系统时间：可结合构建常量、可信网络时间与文件系统时间取最大值（本文 `sub_5D85D0` 的做法），但需处理离线/网络失败场景，避免启动长时间阻塞。
- 反分析与完整性：运行时生成算法常数表、指针间接引用关键变量可提高静态分析成本，但不能替代密码学签名；可配合代码完整性校验、反调试与混淆。
- 检测（防御方视角）：监控 license 文件被替换、注册表/配置文件异常修改、同一 license 在多台机器复用；对“关于”界面中的授权类型/日期与激活记录做一致性校验。
