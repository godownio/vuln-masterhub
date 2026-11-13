---
id: code-analysis-reverse-windows-pe-delay-import-descriptor-tailmerge-iat
title: PE 延迟导入表解析：ImgDelayDescr 数组、__imp_load_ 桩与 __tailMerge/__delayLoadHelper 首次调用回填 IAT
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-delay-import-descriptor-tailmerge-iat-parse
tags:
- reverse
- windows
- pe
- delay-import
- iat
- parser
- loader
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:53:34+08:00'
  notes: 已对照原文与33图核对（图29为DELAY_IMPORT描述符/名称表/UnLoad IAT与__delayLoadHelper关系图）；ImgDelayDescr八字段32B、grAttrs新旧格式、__imp_load_桩→__tailMerge→__delayLoadHelper→jmp eax路径、(IAT槽-rvaIAT)/指针大小反查名字下标均与原文一致（原文按32位/4字节计算）；延迟导入按函数逐一解析与原文一致；与import-reloc-parser卡边界成立（对方仅变体一句提及DataDirectory[13]）；无affected_versions；无PoC
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-delay-import-descriptor-tailmerge-iat/
draft: false
kb_aliases:
- 延迟导入表
- Delay Import
- ImgDelayDescr
- __delayLoadHelper
- __tailMerge
- __imp_load_
- rvaIAT rvaINT
- 延迟加载 DLL
---

## 一句话结论

延迟导入由 `DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT=13]` 指向的 `ImgDelayDescr` 数组描述（每项一个 DLL，字段 `rvaDLLName`、`rvaHmod`、`rvaIAT`、`rvaINT`、`rvaBoundIAT`、`rvaUnloadIAT`、`grAttrs`）；在 DLL 真正被用到前，IAT 槽里放的不是函数地址，而是一段 `__imp_load_<函数>` 桩（`mov eax, offset IAT槽; jmp __tailMerge_<DLL>`）。函数第一次被调用时，`__tailMerge` 压入该 DLL 的 `ImgDelayDescr` 并调用 `__delayLoadHelper`，由它 `LoadLibrary`/`GetProcAddress` 解析函数并回填 IAT，之后 `jmp eax` 进入真实函数，不再走 helper。分析延迟导入样本要按这套“桩 + 描述符 + helper”路径看，而不是只看加载后的 IAT。

## 原理

- **为什么有延迟导入**：程序导入的 DLL/函数很多但并非每次都用到；延迟导入把“加载 DLL + 解析函数”推迟到第一次实际调用，加快启动。`DataDirectory[13]` 的 `VirtualAddress` 指向 `ImgDelayDescr` 数组（和导入表一样以全 0 项结束），每项对应一个延迟加载的 DLL。
- **`ImgDelayDescr` 字段**（新版本 `grAttrs=1`，各 `rva*` 均为 RVA；旧版本 `grAttrs=0` 时相应字段是 VA/指针）：
  - `rvaDLLName`：DLL 名字符串 RVA；
  - `rvaHmod`：存放模块基址（HMODULE）的变量 RVA，加载前为 NULL，加载后写入真实基址；
  - `rvaIAT`：延迟导入 IAT 的 RVA（加载前是桩地址数组，加载后是函数地址数组）；
  - `rvaINT`：延迟导入名称表（INT）RVA，元素为 `IMAGE_IMPORT_BY_NAME` 指针/偏移；
  - `rvaBoundIAT`：可选的绑定 IAT；
  - `rvaUnloadIAT`：可选的原始 IAT 副本（Unload IAT Table，供卸载时恢复桩）；
  - `dwTimeStamp`：绑定时间戳，0 表示未绑定。
- **加载前的调用路径**：反汇编原文示例（`wininet.dll` 的 `InternetConnectA`）：
  ```asm
  __imp_load__InternetConnectA@32:
      mov     eax, offset __imp__InternetConnectA@32   ; IAT 槽地址
      jmp     __tailMerge_WININET
  __tailMerge_WININET:
      push    ecx
      push    edx
      push    eax                                      ; 要解析的 IAT 槽地址
      push    offset __DELAY_IMPORT_DESCRIPTOR_WININET ; 本 DLL 的 ImgDelayDescr
      call    __delayLoadHelper
      pop     edx
      pop     ecx
      jmp     eax                                      ; 跳入真实函数
  ```
  `__delayLoadHelper` 内完成加载 DLL、查导出、填 IAT，并返回函数地址。
- **如何知道要解析哪个函数名**：`__tailMerge` 只传了“IAT 槽地址”和“描述符”，没传函数名。因为 `rvaIAT` 指向该模块第一个导入函数的 IAT 项，按 `(要解析的 IAT 项 RVA - rvaIAT)/指针大小` 得到该函数在 IAT 数组中的下标；`rvaINT` 的名字表与 IAT 顺序相同，用同一下标即可取到函数名，再 `GetProcAddress`。
- **粒度**：延迟导入是“按函数”首次调用时解析——第一次调用某函数才加载 DLL/解析该函数并回填对应 IAT 项；之后的调用直接跳真实地址，不再经过 `__delayLoadHelper`。
- **分析价值**：静态 IAT 中看不到真实 API（只有 `__imp_load_` 桩），依赖 IAT 的能力评估会漏报；延迟导入目录也是判断样本“隐藏 API 使用”的一个入口。

## 触发条件

- 目标 PE 存在 `DataDirectory[13]`（延迟导入目录）且 `VirtualAddress/Size` 非零；常见于使用 `/DELAYLOAD` 的工程（如 wininet、comctl32 等）。
- 需要恢复/枚举真实导入函数（恶意样本能力分析、脱壳后 IAT 重建、调试下断点）。
- 目标可能为旧版 `grAttrs=0`（字段是 VA）或新版 `grAttrs=1`（RVA），需按属性区分。

## 利用步骤

1. 从 `DataDirectory[13]` 取出延迟导入描述符数组的文件偏移/RVA，按 32 字节（`ImgDelayDescr`）逐项读取，遇到全 0 描述符结束。
2. 每项记录 `grAttrs`（0 旧/1 新）、`rvaDLLName`、`rvaHmod`、`rvaIAT`、`rvaINT`、`rvaBoundIAT`、`rvaUnloadIAT`、`dwTimeStamp`；按属性决定字段按 RVA 还是 VA 解析。
3. 枚举 `rvaIAT` 数组：加载前各项指向 `__imp_load_<函数>` 桩（或未解析占位）；`rvaINT` 数组按相同顺序保存 `IMAGE_IMPORT_BY_NAME`（首字段 `Hint`，后跟名字符串），据此还原“IAT 槽 → 函数名”。
4. 对应到代码中的 `__imp_load_` / `__tailMerge_` 桩：静态定位这些桩即可知道哪些调用会触发延迟解析；动态可在 `__delayLoadHelper`、`LoadLibrary/GetProcAddress` 或目标 DLL 的 `DllMain` 下断点，首次调用时观察回填的 IAT 值。
5. 解析完成后（或 hook 掉 helper 后）读取 `rvaHmod` 中的模块基址与 IAT 真实地址，完成 IAT 重建/能力枚举。
6. 注意与绑定导入（`DataDirectory[11]`，`IMAGE_BOUND_IMPORT_DESCRIPTOR`）区分：绑定导入是加载前预先修正 IAT，延迟导入是首次调用时才修正。

## PoC

无 PoC（结构说明与反汇编路径；原文未提供可运行脚本）。分析核对点：

```text
DataDirectory[13] -> ImgDelayDescr[] (全 0 结束)
  grAttrs=1: rvaDLLName / rvaHmod / rvaIAT / rvaINT / rvaBoundIAT / rvaUnloadIAT / dwTimeStamp(32B)
IAT 槽 RVA 与桩:
  __imp_load_<fn>: mov eax, offset <IAT槽>; jmp __tailMerge_<DLL>
  __tailMerge: push 描述符 + IAT槽 -> call __delayLoadHelper -> jmp eax
名字索引: (IAT槽RVA - rvaIAT) / sizeof(ptr) -> rvaINT 同名下标
```

## 变体与关联

- **普通导入/绑定导入/重定位**：[[code-analysis-reverse-windows-pe-import-reloc-parser]] 解析 `DataDirectory[1]/[11]/[5]`（ILT/IAT、绑定导入、`.reloc`）；本卡是其未展开的 `DataDirectory[13]` 延迟导入分支，补上 `ImgDelayDescr`、`__tailMerge` 与首次调用回填机制。
- **IAT 重建/修复**：[[code-analysis-reverse-windows-pe-import-table-encrypt-unpack-section-iat-rebuild]]、[[code-analysis-reverse-unpacking-ollydbg-run-trace-condition-importrec-tracer]] 等脱壳场景需要同时处理普通导入与延迟导入；只重建普通 IAT 会漏掉延迟导入项。
- **API 隐藏**：恶意样本故意使用延迟导入或自行解析 API（[[code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea]] 一类 IAT Hook/动态解析）时，静态 IAT 只能看到桩；`__imp_load_`/`__tailMerge` 字符串与 `DataDirectory[13]` 是补充线索。
- **边界**：`grAttrs=0` 的旧格式字段含义不同（指针而非 RVA）；`rvaBoundIAT`/`rvaUnloadIAT` 可能为空；不同编译器/CRT 的 `__tailMerge` 符号命名与寄存器保存序列略有差异。

## 检测与防御

- **检测**：检查 `DataDirectory[13]` 是否非零、节中出现 `__imp_load_`/`__tailMerge`/`__delayLoadHelper` 符号/字符串；加载后对比 IAT 槽是否从桩地址变为模块外地址；动态监控 `LoadLibrary`/`GetProcAddress` 的延迟调用时机。
- **分析建议**：能力评估不要只看静态 IAT；把延迟导入、`GetProcAddress` 动态解析、API 哈希解析一起纳入（见关联卡）。
- **防御/开发**：延迟导入本身是合法优化，不构成风险；对可疑延迟加载的 DLL 路径做完整性校验与签名验证；EDR 可对 `__delayLoadHelper` 触发的异常模块加载（非常见路径/未签名）告警。
