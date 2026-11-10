---
id: code-analysis-reverse-windows-pe-section-squeeze-entrypoint-shellcode-patch
title: 手工压缩 PE 节表腾出可执行空隙并改写 AddressOfEntryPoint 注入调用 MessageBoxA 的补丁指令（白程序劫持）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-manual-shrink-entrypoint-patch-shellcode
tags:
- pe
- windows
- reverse
- binary-patch
- entrypoint
- code-injection
- shellcode
- 010editor
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:53:34+08:00'
  notes: 已对照原文核对；注入指令序列（push 0 / 0x010051B0 / 0x010051BB / 0 / call near ptr 77D507EAh / jmp 0x1003E21）、010Editor 改 AddressOfEntryPoint、Process Monitor+AHeadLib.Net 的 DLL 变体均与正文一致；本次核对未读取图片，原文「手工压缩」的具体裁剪步骤与节表改动只在截图中，卡内把「压缩腾出节尾空隙」作为注入位置建立在前文 PE 对齐结构说明之上，属作者推断而非原文逐字给出；未复跑
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-section-squeeze-entrypoint-shellcode-patch/
draft: false
kb_aliases:
- PE 手工压缩
- 改写入口点注入
- AddressOfEntryPoint 补丁
- 白程序代码注入
- 节表空隙利用
- 扫雷注入实验
---

## 一句话结论

PE 文件把「文件对齐」与「内存对齐」不同造成的节尾空隙（slack space）暴露为一处可写可执行区域：手工压缩/裁剪原有节表让某个可执行节腾出几十字节空隙，把 `push/call` 形式的载荷写进空隙，再把 `IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint` 改成该空隙的 RVA，程序启动时就会先执行注入代码、再 `jmp` 回原入口，外观与功能不变——这是对合法可执行文件（含带签名的白程序）做代码注入的最小手法。

## 原理

- **PE 的两套对齐**：`FileAlignment` 决定节在磁盘上按多大粒度对齐，`SectionAlignment` 决定加载到内存时的粒度。磁盘上节的原始大小 `SizeOfRawData` 通常大于实际内容 `VirtualSize`，两者之差即节尾空隙；加载后这段区域落在已映射的可执行页内，因此**不需要改节属性就能直接执行**。
- **为什么先「压缩」**：不是所有程序都有足够大的空隙。手工压缩指裁剪/合并原有节、缩小节表项，把无用空间（如被填充到对齐边界的空白、可安全精简的数据）腾出来，让目标可执行节尾部出现一段连续、未使用的字节区；原文用 010Editor 直接编辑节表与数据。
- **为什么要改入口点**：写入空隙的字节默认不会被执行，必须让加载器从那里开始取值。`AddressOfEntryPoint` 是 RVA，改指向空隙起始地址即可；注入代码末尾 `jmp 原入口 RVA` 保证原逻辑继续，避免程序行为异常被发现。
- **调用外部 API 需要解析地址**：`call MessageBoxA` 这类指令在静态文件中只能写死目标地址。原文通过动态调试查看 `MessageBoxA` 在 `user32.dll` 载入后的实际地址（如 `77D507EA`），再把 `call` 指令的操作数写成该绝对值——因此这种补丁**与系统和 DLL 版本绑定**，换机器或 ASLR 变化后地址失效（这也是 `call` 前需要固定基址/关闭 ASLR 或改用 `call [IAT]` 的原因）。
- **白程序利用价值**：被补丁的程序本身签名、版本、功能都正常，入口点 patch 发生在 `main` 之前，静态对比哈希才可见；攻击者用它承载任意载荷（shellcode/下载器），比新投放未知 EXE 更隐蔽。

## 触发条件

- 攻击者能修改目标可执行文件（本地投放、供应链替换、更新包劫持等）。
- 至少有一个可执行节存在足够大的尾部空隙（或可通过裁剪节表腾出），空隙长度容得下注入代码 + 回跳指令。
- 注入代码若调用系统 API，需要目标机器上 `user32.dll` 等模块基址与调试机一致（或改写为 `call [IAT]`/运行时解析）。
- 程序未做完整性自校验（校验和、签名验证、嵌入哈希），否则补丁导致启动失败或告警。

## 利用步骤

1. 用 PE 解析工具（010Editor 模板 / PE-bear / CFF Explorer）查看节表：记录各节 `VirtualSize`、`SizeOfRawData`、`Characteristics`，找带 `IMAGE_SCN_MEM_EXECUTE` 且尾部有空白字节的节。
2. 若空隙不足，手工压缩：裁掉节尾填充、合并可精简数据，缩小对应 `SizeOfRawData`，使目标节尾部出现一段连续空白（原文即「手工压缩」腾空间）。
3. 在数据段找一处空白写入字符串参数（如弹窗标题/内容）。
4. 动态调试确认要调用的 API 实际地址，构造注入指令：`push 0`（uType）、`push 标题地址`、`push 内容地址`、`push 0`（hWnd）、`call MessageBoxA 地址`、`jmp 原入口 RVA`。
5. 把这段机器码写入空隙，记录其 RVA。
6. 修改 `IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint` 为该 RVA，保存。
7. 运行验证：先弹出消息框，关闭后程序继续正常运行（原文对扫雷程序验证成功）。

## PoC

```text
; 注入到节尾空隙的指令序列（地址为原文动态调试所得）
push 0
push 0x010051B0        ; 标题字符串（数据段空白处）
push 0x010051BB        ; 内容字符串
push 0
call near ptr 77D507EAh  ; MessageBoxA 实际地址
jmp  0x1003E21         ; 回跳原入口点
```

```text
; 随后用 010Editor 把 AddressOfEntryPoint 改成上述指令所在 RVA，保存即生效
```

原文对 DLL 变体给出的是另一条路径（`Process Monitor` 找依赖的系统 DLL，用 AHeadLib.Net 生成代理源码，在 `__ExecuteUserCutomCodes` 里加 `system("calc.exe")` 后编译，替换同级目录 DLL 触发），属代理 DLL 劫持，与本节入口点补丁是两种独立手法。

## 变体与关联

- **写入位置变体**：节尾空隙、新增/扩展节、`.text` 代码洞（code cave）、TLS 回调；改 `AddressOfEntryPoint` 之外还可改 TLS 回调指针、`.init_array`/CRT 初始化函数，静态对比入口点看不出来。
- **回跳方式变体**：`jmp 原 OEP`、`push 原OEP; ret`、调用约定允许时直接 `ret`；需要保存/恢复寄存器时在头尾加 `pushad/popad`。
- **API 地址变体**：写死绝对地址（换机器失效）、`call dword ptr [IAT 项]`（与导入表一致，更稳）、或运行时 PEB 遍历 + 导出表解析（位置无关）。
- 关联（同一 sink 的不同做法，已对比后仍单独成卡）：`pentest/c2` 下「签名 EXE 入口点/函数补丁 + 回写证书表」与「两阶段函数补丁跳板」都是用工具把 shellcode 写进已有 PE 后改入口或改被调函数，起点是**已有足够空间/已有大函数**；本卡的前提不同——先用**手工压缩节表**造出可执行空隙，载荷是调用系统 API 的少量补丁指令而不是完整 shellcode，也不涉及签名与 C2，所以作为 PE 结构层面的入门做法独立保留。其余关联：`code-analysis/reverse/windows` 下 PE 头布局、导入表解析、`.text` 代码洞 patch 卡；代理 DLL 侧加载见 `pentest/persistence` 下 DLL 搜索顺序劫持卡（即原文的另一个 DLL 变体）。
- 边界：启用 ASLR/CFG 且调用绝对地址时失效；有空隙但落在不可执行页（节特性无 EXECUTE）时不能直接执行；带完整性校验（签名校验、Authenticode 校验、内嵌哈希）或被打包器加密的样本需先脱壳/修复。

## 检测与防御

- 检测：`AddressOfEntryPoint` 不落在任何正常代码节起始处、或落在节尾 `SizeOfRawData - VirtualSize` 空隙内；入口点字节不是编译器常见序言（`push ebp; mov ebp, esp` 或 `sub rsp, xx`）；同一文件的 `SizeOfRawData` 与 `VirtualSize` 关系异常（手工压缩痕迹）；签名有效但文件哈希与官方发布不一致；进程启动早期（`main` 前）出现网络/文件行为。
- 防御：对可执行文件做签名校验 + 官方哈希比对（白名单）；启用 CFG/ACG 与代码完整性（HVCI）；不要把可写可执行的空隙留在交付文件里（重新编译时用 `SizeOfRawData == VirtualSize` 或加填充检测）；监控入口点被改写的样本。
