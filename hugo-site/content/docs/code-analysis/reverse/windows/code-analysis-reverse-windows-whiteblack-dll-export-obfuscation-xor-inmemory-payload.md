---
id: code-analysis-reverse-windows-whiteblack-dll-export-obfuscation-xor-inmemory-payload
title: 白加黑安装包：伪装 Setup Factory 安装程序落地私有 DLL，借宿主 EXE 加载后经混淆导出函数 XOR 解密同目录数据并在内存执行第二段
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: whiteblack-dll-obfuscated-export-xor-inmemory-payload
tags:
- windows
- dll-sideload
- white-black
- delphi
- xor
- in-memory-load
- installer-bundling
- malware-analysis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:34:19+08:00'
  notes: 已对照原文核对；本次核对未读取图片；IsWindowServer 导出、Prgkectiodn.u6mg 数据文件、XOR 解密、第二段 Delphi 载荷、互斥体与 Run 键、C2 域名等与正文一致；XOR 密钥与解密循环细节仅截图可见，卡内未落具体常量；PoC 为分析侧复现路径而非可执行样本，未执行文内任何命令
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-whiteblack-dll-export-obfuscation-xor-inmemory-payload/
draft: false
kb_aliases:
- 白加黑加载
- 白加黑 导出函数混淆
- IsWindowServer 导出函数
- Setup Factory 捆绑安装包
- Delphi 恶意 DLL
- 同目录数据文件 XOR 解密
- 内存加载第二段 payload
---

## 一句话结论

攻击者用 Setup Factory 把恶意文件打进"ToDesk 安装包"，安装后由**合法签名的宿主 EXE（白）**去加载同目录下的**恶意 DLL（黑）**，恶意 DLL 的导出表被人为混淆成大量随机名，真正的入口藏在一个伪装成系统 API 的导出（`IsWindowServer`）里：它读取同目录的加密数据文件（`Prgkectiodn.u6mg`）到内存，用 XOR 解密出第二段 Delphi 载荷，再直接调用其导出函数在内存执行——全程不落第二个可执行文件，静态扫描只看到一个正常安装程序加一个"私有 DLL"。

## 原理

- **白加黑为什么能过签名校验**：Windows 只校验被加载模块自身的签名/信誉，宿主 EXE 是正版签名文件，攻击者替换的只是它要加载的 DLL；用户看到的是"知名软件的安装包"，杀软看到的是一次正常的 DLL 加载。
- **导出名混淆的动机**：DLL 的导出表是静态分析的第一落点。把导出改名成 `IsWindowServer`、`M78E27BDC3EF60E302EDD6DD505E10A2F22D17DD23AF703GYT` 这类"像系统 API / 像随机哈希"的名字，既让批量特征匹配失效，又让分析者难以从名字判断哪个导出是入口——误导性命名本身是免杀手段。
- **为什么入口必须在导出里**：宿主 EXE 通过 `GetProcAddress` 调导出，所以 loader 逻辑天然位于某个导出函数内；找出"哪个导出被调用"等价于找到载荷入口，这也是分析此类样本的最小路径。
- **XOR 加密数据文件的意义**：第二段载荷以密文形式落在磁盘上（不是 PE 头，YARA/AV 的 PE 特征匹配不到），解密后才在内存中成形；XOR 是单字节/短密钥，逆向时一旦拿到密钥与解密函数即可完整还原，属于"低强度但足够躲静态特征"的混淆。
- **内存执行的收益**：直接 `call` 第二段的导出函数（而不是 `CreateProcess`/`WriteFile+LoadLibrary`），进程链上没有新进程、文件系统上没有新落盘文件，行为检测只有一次 DLL 加载加一次可疑文件读取。
- **为什么 Delphi 载荷重要**：Delphi 编译的远控/盗币模块在 VT 上检出率通常偏低（字符串与 RTTI 形态与 MSVC/.NET 样本差异大），攻击者选它是为了压检出。

## 触发条件

- 受害者执行了捆绑恶意文件的"正版软件安装包"（本例 Setup Factory 打包），安装目录内被写入宿主 EXE + 恶意 DLL + 加密数据文件。
- 宿主 EXE 以"同目录优先"方式加载该 DLL 名（DLL 搜索顺序/侧加载），且未做签名或哈希校验。
- 恶意 DLL 具备读取同目录文件的权限（安装目录通常可写），且第二段载荷的导出名与调用约定与 loader 一致。

## 利用步骤

1. 用安装包/捆绑工具把正版安装程序与恶意文件一起打包，安装后布局为：宿主 EXE、`dev\` 子目录下的恶意 DLL、同目录加密数据文件。
2. 恶意 DLL 用 Delphi 编写，编译时间可伪造；导出表批量改名，把 loader 藏在最像系统 API 的导出里。
3. loader 读取同目录数据文件到内存，用内置算法（本例 XOR）解密出第二段 PE/DLL，`LoadLibrary`/手动映射后按导出名调用其入口。
4. 第二段载荷创建互斥体（单实例）、写自启动注册表项，采集 OS 版本/类型/GUID/BIOS 信息，进入远控指令循环。
5. 远控指令集里包含"钱包/浏览器数据窃取"分支（见关联卡），最终把敏感数据外传至 C2 域名。

## PoC

```text
# 分析侧最小复现路径（不执行样本）
1) 安装包解包 -> 得到宿主 EXE + dev\*.dll + <随机名>.u6mg
2) dumpbin /exports dev\*.dll            # 观察导出名是否成批混淆、是否混入 IsWindowServer 等伪系统 API
3) 在 IDA 中按 xrefs 定位被宿主 EXE GetProcAddress 引用的导出 -> 即 loader
4) 提取数据文件 + 复刻 XOR 循环 -> 得到第二段 PE/DLL（本篇为 Delphi 编译）
5) 对第二段查互斥体字符串、Run 键路径、指令分发表与 C2 域名
```

```text
判据：dev 目录下 DLL 的导出名呈现"大量等长随机串 + 少量貌似系统 API"的混合形态；
loader 导出内部出现 同目录文件名常量 + 字节循环 XOR + 对解密缓冲区的执行/加载调用；
第二段不落盘却能创建互斥体与 Run 键。
```

## 变体与关联

- 关联：[[pentest-persistence-dll-search-order-hijack-proxy-forwarding]]（DLL 搜索顺序劫持与导出转发的持久化视角，本卡是"打包分发 + 导出名混淆 + 内存加载"的样本侧视角）、[[code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation]]（同类侧加载手法的另一家族）、[[defense-forensics-wallet-extension-id-local-extension-settings-collection]]（本条链的第二段载荷落地功能：按扩展 ID 定位钱包数据）。
- 变体：数据文件可换成资源段/RDOS 附加数据/注册表值；XOR 可换成 RC4/TEA 或"密钥来自 MachineGuid"；第二段可改为反射式 PE 内存加载（无需导出调用）。
- 边界：宿主 EXE 若校验 DLL 签名或改为绝对路径加载，白加黑失效；数据文件若被杀软按"同目录异常二进制"规则拦截，loader 读不到密文；第二段若依赖特定 Delphi RTL 版本，换环境可能崩。

## 检测与防御

- 检测：安装目录内出现"签名 EXE + 无签名 DLL + 非 PE 数据文件"三件套；DLL 导出名大批随机且混入伪系统 API 名；进程读取同目录陌生扩展名文件后立即出现 `LoadLibrary`/内存执行行为；无文件落盘却新建 Run 键与互斥体。
- 防御：对安装目录内 DLL 做签名/哈希白名单校验（或用 `SetDefaultDllDirectories` + 绝对路径加载）；禁止在用户可写目录加载模块；监控 Run 键与互斥体创建；对"安装包分发 + 侧加载"组合做供应链来源核验；企业侧启用 DLL 加载审计与内存扫描。
