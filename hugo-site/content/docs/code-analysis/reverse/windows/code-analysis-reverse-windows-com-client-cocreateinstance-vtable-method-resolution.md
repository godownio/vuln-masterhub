---
id: code-analysis-reverse-windows-com-client-cocreateinstance-vtable-method-resolution
title: COM 客户端静态分析：CoCreateInstance 的 CLSID/IID 解析、ppv 接口类型修复与虚表偏移方法定位
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: com-client-cocreateinstance-vtable-method-resolution
tags:
- reverse
- windows
- com
- ida
- cocreateinstance
- clsid
- iid
- vtable
- malware-analysis
- shell-application
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T08:28:28+08:00'
  notes: 已对照原文与图21-30核对：CoCreateInstance 的 CLSID/IID 查注册表与 TypeLib、ppv 类型修为 IShellDispatch、虚表偏移36=Namespace、返回 Folder 后 CopyHere，以及 COMView/comida/IDA8.3 工具链均与原文一致；已将伪代码中误写的 CLSCTX_LOCAL_SERVER 修正为 CLSCTX_INPROC_SERVER（原文样本 dwClsContext=1u，shell32 为 in-proc 服务器，KB与staging同步修正）。与 COM 激活子进程跟踪/OCX CLSID 加载卡为不同分析方法，非重复；原文无版本，未设 versions
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-com-client-cocreateinstance-vtable-method-resolution/
draft: false
kb_aliases:
- IDA 分析 COM 调用
- CoCreateInstance 逆向
- CLSID 解析
- IShellDispatch 虚表
- ppv 接口修复
- COMView 查接口
- comida 插件
- Shell.Application 静态分析
---

## 一句话结论

分析 Windows 样本的 COM 调用时，先在 IDA 中定位 `CoCreateInstance(CLSID, ..., IID, &ppv)` 并取出两个 GUID 常量：用 CLSID 在注册表/COMView 中查到 ProgID、`InProcServer32` 与 TypeLib，确认组件身份（如 `{13709620-C279-11CE-A49E-444553540000}` 是 ShellAutomation Service / `shell32.dll`），再把 `ppv` 变量类型改为对应接口（如 `IShellDispatch`），借助 TypeLib 的虚表偏移（如 offset 36 = `Namespace`）与返回值类型（`Folder`）恢复方法调用，就能把样本「用 Shell 把窃取目录打包成 zip」的行为完整还原。

## 原理

- **COM 二进制调用约定**：`CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)` 的第 1 个参数是 CLSID（类标识），第 4 个是 IID（接口标识），第 5 个 `ppv` 返回接口指针；接口指针指向的虚表首地址处按固定偏移排列方法，调用形式为 `ppv->lpVtbl->Method(...)`。没有类型信息时 IDA 只能显示 `(*(...)(...))` 式的间接调用。
- **反查组件身份**：`HKCR\CLSID\{GUID}` 下有 `ProgID`、`InProcServer32`（组件 DLL 路径，如 `C:\Windows\System32\wshom.ocx` 或 `shell32.dll`）、`TypeLib`（类型库 GUID）；`HKCR\TypeLib\{GUID}\<ver>\<lcid>\win32|win64` 指向带类型库的 DLL/OCX。注意 32/64 位注册表视图（SysWOW64 vs System32）。
- **TypeLib 给出接口与方法**：Shell 自动化 CLSID `{13709620-C279-11CE-A49E-444553540000}` 对应 `IShellDispatch`（IID `D8F015C0-C278-11CE-A49E-444553540000`）；TypeLib 中可见 `Namespace` 位于虚表偏移 36（0x24），返回 `Folder`；`Folder.CopyHere` 则把源文件/目录复制到目标 Folder。
- **变量类型修复**：把 `ppv` 声明为 `IShellDispatch *` 后，IDA 能正确反编译 `ppv->lpVtbl->Namespace(...)`；若组件实现多个接口，必须结合 IID 二次判定，否则会把方法偏移套错接口。
- **返回值类型链**：`Namespace` 返回的 `Folder` 再作为下一层对象，继续把变量类型改为 `Folder *` 即可看到 `CopyHere`（以及 `CopyThis`、`MoveHere` 等）调用。
- **工具与插件**：COMView/oletviewdotnet 可浏览已注册 COM 类的 CLSID、TypeLib、接口与方法；IDA 8.3 起对 CLSID/IID 常量有更好的自动解析；comida 插件可加载 TypeLib 批量修复 COM 调用类型。
- **动态验证**：在 xdbg 中对 `CoCreateInstance` 下断，检查 `ppv` 指向、接口虚表与参数（如 `SysAllocString` 传入的 zip 路径），可确认静态分析结论。

## 触发条件

- 有一个调用 COM 的 Windows PE 样本，且未加壳/已脱壳到可读代码。
- 分析机有 IDA/Ghidra、目标组件的 TypeLib（系统组件通常自带）以及 COMView/oletviewdotnet 等工具。
- 样本中 CLSID/IID 以常量或可解密数据出现；若被混淆需先还原。

## 利用步骤

1. 在导入表/调用点定位 `CoCreateInstance`（或 `CoCreateInstanceEx`、`CoGetClassObject`），提取 CLSID 与 IID 常量。
2. 用注册表编辑器在 `HKCR\CLSID\{CLSID}` 查看默认名、`ProgID`、`InProcServer32`、`TypeLib`；或在 COMView 中按 CLSID 搜索。
3. 通过 TypeLib 打开对应接口，记录 IID、方法名与虚表偏移（如 `IShellDispatch.Namespace` = 36）。
4. 在 IDA 中把 `ppv` 变量类型改为 `<Interface> *ppv`；若调用偏移与方法不符，用 IID 确认接口是否选错。
5. 跟随返回值：把 `Namespace` 的返回变量改为 `Folder *`，恢复 `CopyHere` 等调用，并记录参数（源路径、目标 zip 路径）。
6. 动态验证：xdbg 断在 `CoCreateInstance` 之后，检查 `ppv` 与虚表，或直接观察样本生成的 zip 文件内容。
7. 对未知 CLSID，可用 PowerShell `[type]::GetTypeFromCLSID()` 尝试创建并枚举对象方法辅助确认。

## PoC

静态映射示例（Shell 自动化）：

```text
CLSID {13709620-C279-11CE-A49E-444553540000} -> ShellAutomation Service（shell32.dll）
IID   {D8F015C0-C278-11CE-A49E-444553540000} -> IShellDispatch
IShellDispatch 虚表 offset 36 (0x24) -> Namespace(Variant) -> Folder*
Folder 方法 -> CopyHere(Variant, Variant)
```

IDA 伪代码形态（变量类型修复后）：

```c
CoCreateInstance(&clsid, 0, CLSCTX_INPROC_SERVER, &iid, (void **)&ppv);
VARIANT arg; VariantInit(&arg);
arg.bstrVal = SysAllocString(zip_path);
Folder *folder = ppv->lpVtbl->Namespace(ppv, arg);
folder->lpVtbl->CopyHere(folder, src_variant, 0);
```

原文按此流程还原了 Lokibot 的 Shell 自动化 zip 打包行为并动态复现；本卡未复跑样本。

## 变体与关联

- **其它 COM 组件**：WScript.Shell（`{72C24DD5-D70A-438B-8A42-98424B88AFB8}`，`wshom.ocx`）提供 Run/Exec；XMLHTTP/ADODB 等组件也可用同样方法还原。
- **服务型 COM**：`CoCreateInstance` 可能拉起独立宿主进程（如 svchost/TiWorker），需结合父进程 `CreateProcessInternalW` 跟踪（已有 COM 激活分析卡）。
- **COM 劫持**：若注册表 CLSID 的 `InProcServer32` 指向缺失/可控路径，可作为持久化与加载点（已有 OCX/CLSID 加载卡）。
- **关联卡**：Shell.Application CopyHere 打包 zip 的利用技术。

## 检测与防御

- 该卡是分析/取证方法，不直接产生攻击面；防御侧关注样本的实际 COM 行为。
- **检测**：脚本/样本创建 `Shell.Application`（CLSID `13709620-...`）、调用 `Namespace`/`CopyHere`、在 AppData 生成 zip；EDR 的 COM 对象创建与 ScriptBlock 日志可覆盖。
- **防御**：限制不必要的 Shell COM 自动化与脚本宿主；对注册表 CLSID 的异常修改（指向用户可写路径）告警；出网/DLP 监控压缩包外传。
