---
id: defense-forensics-agenttesla-dotnet-smtp-credential-resource-decrypt
title: Agent Tesla 内存邮箱取证：套壳提取 .NET 母体后，dnSpy 替换资源号解密 SMTP NetworkCredential 账号与口令
type: scenario
domain: defense
path: defense/forensics
technique: agenttesla-dotnet-smtp-credential-resource-id-decrypt
tags:
- forensics
- memory
- malware
- agenttesla
- dotnet
- smtp
- credential
- resource-decryption
- dnspy
- unpacking
- stealer
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V538
  verified_at: '2026-11-11T18:58:15+08:00'
  notes: 已对照原文与全部17张截图核对：图01 DIE 识别 Borland Delphi(7)/Turbo Linker Delphi EXE32；图02 Dark 3.50 D7 模块列表；图03 OD VirtualAlloc 后 CALL EAX 进入 shellcode；图04-06 内存解密出 MZ/PE 二阶段（DIE 显示 Microsoft Visual C++(2008)、348672 字节）；图07 入口点 switch 混淆；图08 俄语字符串；图09 schtasks 局部变量 @"/Create /TN \"Updates\""、@"C:\Users\Administrator\AppData\Local\Temp\tmp24AC.tmp"；图10 ShellExecuteOnSTAThread 的 ThreadStart+SetApartmentState(STA)+Start/Join；图11 SMTP 函数 tyx(string tdc, string tdj, MemoryStream tdo=null, int td1=0) 中 NetworkCredential(<Module>.\u0005(487680), \u0005(487648))、Host=\u0005(488000)；图12-13 资源解密包装 \u0005(int A_0) 调 \u0004(array3,array4,array5)+Encoding.UTF8.GetString；图14 断点局部值 540416 与『替换成账号密码的资源编码』；图15-17 GetString(bytes,0,bytes.Length) 返回处 bytes 内存可见 lee_yokeeng@kanzen.com.my 与 YeeLee@1919.。资源号、函数名、账号口令样例与卡片一致；affected_versions 不设置（恶意样本，原文未给版本）。修正两处措辞：鹰眼 RAT 改为原文『大同小异』的忠实表述；VMVMVM 字符串位置由『内存中』改为原文『调试器中』。dedup：唯一 related 为 defense-detection-agenttesla-web-panel-stealer-behavior-ioc（同家族检测/IOC，入口与目标不同），其余为
    AgentTesla 阶段 DLL 还原、多阶段资源 dump、批量静态配置抽取等不同手法，非同链。未验证点：未运行样本，依赖原文调试截图。
url: /docs/defense/forensics/defense-forensics-agenttesla-dotnet-smtp-credential-resource-decrypt/
draft: false
kb_aliases:
- Agent Tesla 邮箱取证
- Agent Tesla SMTP 凭据提取
- 资源号替换解密
- dnSpy 资源解密取证
- NetworkCredential 资源 ID
- Tesla 内存邮箱
---

## 一句话结论

Agent Tesla 的多阶段套壳最终释放 .NET 母体，其 SMTP 发送函数用 `new NetworkCredential(<Module>.\u0005(487680), <Module>.\u0005(487648))` 从加密资源中取账号/口令，`Host` 取 `\u0005(488000)`；取证时在 dnSpy 定位资源解密包装函数，把调用处的资源号（如 540416）替换为账号资源号 487680、在 `GetString` 的 `return` 下断，运行后即可从返回的 `bytes` 读出 UTF-8 明文账号；重启后同法取口令资源 487648，从而拿到攻击者的匿名/二级邮箱凭据。

## 原理

- **Agent Tesla 的窃取通道**：Agent Tesla 是 2014 年起活跃的 .NET 信息窃密 RAT，回传方式包括 SMTP 邮件、FTP、HTTP/Web Panel；攻击团队常使用匿名邮箱或二级邮箱接收数据，因此从样本中还原该邮箱凭据对溯源与损失评估价值很高。同类 RAT（如鹰眼 RAT）也以类似方式窃取数据（原文称『大同小异』，未展开其资源加密细节）。
- **套壳与母体提取**：原文样本首阶段为 Borland Delphi（DIE 识别为 `Borland Delphi (7)`/Turbo Linker Delphi EXE32）；OD 在 `VirtualAlloc` 下断、跟两步即可进入 shellcode，shellcode 动态取 API 地址后释放第二阶段 PE；套壳含反调试与虚拟机检测（调试器中出现 `VMVMVM`/`KVM-XEN-VMwer` 等字符串时直接抹除），并解密资源释放 `.pdf` 诱饵、`ShellExecute` 执行；二阶段 PE 多带 UPX 壳，脱壳后即为 .NET 母体（de4dot 去混淆后可见大量俄语字符串）。
- **持久化**：.NET 母体从 XML 资源导入计划任务（`schtasks /Create /TN "Updates\" ... /XML ...`，临时文件如 `%LocalAppData%\Temp\tmp24AC.tmp`），并在 `%APPDATA%\Roaming\Microsoft\Windows\Recent` 生成快捷方式；`ShellExecuteOnSTAThread` 通过 `ThreadStart + SetApartmentState(STA) + Start/Join` 调用 `ShellExecuteFunction`。
- **资源加密结构**：字符串资源（SMTP 账号/口令/服务器等）以整型资源 ID 存储，由包装函数 `\u0005(int A_0)` 调用 `\u0004(array3, array4, array5)` 解密，再 `Encoding.UTF8.GetString(...)`；底层 `GetString(byte[] bytes)` 只是 `GetString(bytes, 0, bytes.Length)`，最终 `new string(this.GetChars(bytes, index, count))`。因此只要让程序用目标资源号走同一解密路径，就能得到对应明文。
- **SMTP 资源号**：反编译的 SMTP 函数 `tyx(string tdc, string tdj, ...)` 中 `new NetworkCredential(<Module>.\u0005(487680), <Module>.\u0005(487648))`、`smtpClient.Host = <Module>.\u0005(488000)` —— 487680 为账号、487648 为口令、488000 为服务器资源号。
- **为什么要动态替换资源号**：静态反编译只能看到 `\u0005(487680)` 这类调用与加密后的资源字节，无法直接得到明文；而资源解密函数是通用的，把当前正在解密的调用参数替换成凭据资源号，再在 `GetString` 返回处断下读取 `bytes`，即可借助样本自身的解密逻辑还原明文。
- **为什么要重启**：账号与口令分两次调试，原文指出切换资源号后需重启程序重新调试，否则内存中可能提取不到密码资源。

## 触发条件

- 已取得 Agent Tesla 样本（含套壳或已提取出的 .NET 母体），并可在受控分析环境中运行、调试（dnSpy/ILSpy + 调试器）。
- 样本使用 SMTP 方式回传且内置邮箱凭据资源；FTP/HTTP 变体需在对应发送函数上找同类资源号。
- 有本地调试权限；若母体仍有轻量反调试需先处理（原文的套壳反调试主要在 Delphi/shellcode 阶段）。
- 邮箱凭据资源未被额外加密/仅由样本内通用资源解密函数保护（本方法依赖复用其解密路径）。

## 利用步骤

1. 用 DIE 识别首阶段编译器/壳；OD 在 `VirtualAlloc` 下断、跟两步进入 shellcode；遇 `VMVMVM`/`KVM-XEN-VMwer` 等虚拟机检测字符串时在内存中抹除，继续跟踪；解密资源释放 `.pdf` 诱饵与二阶段 PE。
2. 提取二阶段 PE，UPX 脱壳；用 de4dot 去混淆后，dnSpy 打开 .NET 母体。
3. 搜索 `SMTP`/`SmtpClient`，定位发送函数（原文 `tyx`），记录 `NetworkCredential` 的两个资源号（487680、487648）与 `Host` 资源号（488000）。
4. 定位资源解密包装函数 `\u0005(int A_0)`（特点：内部调用 `\u0004(array3,array4,array5)` 并 `return Encoding.UTF8.GetString(...)`）与 `GetString(byte[] bytes)`（末尾 `return this.GetString(bytes, 0, bytes.Length)`），在函数头/`return` 处下断。
5. 运行样本到资源解密调用处，把参数 `A_0` 的资源号改为账号资源号 487680；在 `GetString` 的 `return` 下断，读取 `bytes` 并 UTF-8 解码，得到账号明文（原文示例 `lee_yokeeng@kanzen.com.my`）。
6. 重启样本重新调试（避免内存中提取不到），把资源号改为口令资源 487648，同样在返回处读取口令明文（原文示例 `YeeLee@1919.`）。
7. 视需要同法取 `Host` 资源号（488000）得到 SMTP 服务器；用邮箱凭据登录（若仍有效）查看外发邮件、进一步溯源。
8. 自动化思路：阶段一用轻量级沙箱 + 关键 API Hook/内存 PE 扫描自动 dump 内存加载的 .NET PE；阶段二用基于 ILSpy/dnSpy 的 .NET 反汇编 Hook 调试器识别邮箱/FTP 等资源 ID，统一调用解密函数批量提取。

## PoC

无固定 PoC（依赖具体样本），关键断点与代码位置如下：

```csharp
// SMTP 发送函数：账号/口令/服务器均为资源号
SmtpClient smtpClient = new SmtpClient();
NetworkCredential credentials = new NetworkCredential(
    <Module>.\u0005(487680),   // 账号资源号
    <Module>.\u0005(487648));  // 口令资源号
smtpClient.Host = <Module>.\u0005(488000);

// 资源解密包装：把 A_0 改成 487680 / 487648 后单步
internal static string \u0005(int A_0)
{
    object[] u202A = <Module>.‪;
    if (Assembly.GetExecutingAssembly() == Assembly.GetCallingAssembly())
    {
        byte[] array3; byte[] array4; byte[] array5;
        ...
        return Encoding.UTF8.GetString(<Module>.\u0004(array3, array4, array5));
    }
    return "";
}

// 底层 GetString：在此处 return 下断读 bytes
public virtual string GetString(byte[] bytes)
{
    ...
    return this.GetString(bytes, 0, bytes.Length);
}
```

- 原文调试时 `\u0005` 的 `A_0` 当前值为 540416（其他字符串资源），替换成 487680 后断在 `GetString` 返回处，`bytes` 即账号；重启后替换成 487648 取口令。
- 资源号因样本而异，需按目标样本 `NetworkCredential` 调用处的实际整型值替换。

## 变体与关联

- 变体：FTP/HTTP/Web Panel 回传的 Tesla 变体，在对应发送函数（FTP 客户端、HTTP POST 配置）中找同样的资源解密调用与凭据资源号，方法一致。
- 变体：若样本对资源做二次加密（非通用资源解密路径），需先逆出密钥再批量解密；静态批量抽取思路见关联卡。
- 关联：[[code-analysis-reverse-unpacking-agenttesla-stage-dll-xor-subtract-archive]]（Agent Tesla 阶段 DLL 的资源解密/归档还原，本卡前置的母体获取）；[[code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump]]（多阶段 .NET 资源加载与 dnSpy 逐阶段 dump）。
- 关联：[[code-analysis-reverse-windows-dotnet-batch-ilspycmd-config-regex-extract]]（ilspycmd 批量静态抽取 SMTP/FTP 配置，与本卡动态资源号替换互补）；[[defense-detection-agenttesla-web-panel-stealer-behavior-ioc]]（同家族的检测与 IOC）。

## 检测与防御

- 检测（针对 Tesla 主机行为）：计划任务名 `Updates`、`schtasks /Create ... /XML` 调用与 `%LocalAppData%\Temp\tmp*.tmp` 落地；`Recent` 目录异常快捷方式；`ShellExecuteOnSTAThread` 相关进程链；SMTP 出站（25/465/587）到匿名邮箱服务商。
- 检测（取证侧）：内存/进程中出现 `SMTP`、`NetworkCredential`、`SmtpClient` 与高熵资源字节；提取到的邮箱地址/口令可用于邮件服务商侧审计与溯源。
- 防御：拦截来源不明的 Delphi/Go/Rust 套壳样本与 UPX 二阶段 PE；对计划任务与启动目录做完整性监控；企业邮件网关限制/审计匿名邮箱 SMTP 外发，启用出站 25 端口限制。
- 响应：确认凭据后立即锁定/回收该邮箱，排查同源样本投递链与其他失陷主机；若邮箱仍可登录，保留邮件证据后再处置。
