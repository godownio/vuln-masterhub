---
id: code-analysis-reverse-anti-debug-pid-dll-dllgetclassobject-return-check
title: 沙箱探测：调用 pid.dll!DllGetClassObject 并要求返回 CLASS_E_CLASSNOTAVAILABLE(0x80040111)
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: pid-dll-dllgetclassobject-return-check
aliases:
- pid.dll 沙箱检测
- DllGetClassObject 返回值检测
- 2147746065
- CLASS_E_CLASSNOTAVAILABLE
- COM 导出返回值指纹
- 银狐环境检测
tags:
- windows
- anti-debug
- anti-sandbox
- anti-emulator
- com
- dllgetclassobject
- pid-dll
- silverfox
- malware-analysis
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T12:08:58+08:00'
  notes: 已对照原文与图12-14/16核对：反编译片段 v2=1、memset(v5,0,0x20)、strcpy(pid.dll)/strcpy(DllGetClassObject)、GetProcAddress 调用后 return v3(v5,0i64,&v2) != 0x80040111 || v2；卡片调用形态、CLASS_E_CLASSNOTAVAILABLE 语义、输出指针为空检查均一致。与 code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks 对比：该卡正文不含 pid.dll/DllGetClassObject/80040111 任何字样（仅 notes 提及），故本卡为独立原子，--force 理由成立；与其余 anti-debug 卡检测项不同。未验证点：原文未在真实机/沙箱对比该 API 返回值，pid.dll 在精简系统上的存在性未验证（卡片边界已注明）。dedup 唯一 related 为上述综合卡；dup-scan 无本卡 pair。
---

## 一句话结论

银狐母体加载 `pid.dll` 并取 `DllGetClassObject`，用无效的 CLSID 调用后要求返回 `CLASS_E_CLASSNOTAVAILABLE (0x80040111)` 且输出指针为空；返回值不等或输出非空就 `ExitProcess`，用真实系统 DLL 的 COM 导出行为作为“这不是被 hook/伪造的沙箱”的探针。

## 原理

- **为什么选 `pid.dll`**：`pid.dll` 是 Windows 自带的 Microsoft PID Checker（游戏控制器设备 ID 相关）组件，导出标准 COM 入口 `DllGetClassObject`。对不存在的类调用时，真实系统返回 `CLASS_E_CLASSNOTAVAILABLE`（`0x80040111`），并把输出接口指针置空。
- **样本的调用形态**：反编译伪代码为
  ```c
  v2 = 1;                  // 输出指针初值
  memset(v5, 0, 0x20);     // 全零 CLSID 缓冲
  strcpy(v1, "pid.dll");
  strcpy(v4, "DllGetClassObject");
  v3 = GetProcAddress(LoadLibraryA(v1), v4);
  return v3(v5, 0i64, &v2) != 0x80040111 || v2;
  ```
  上层根据返回值决定是否继续；`!= 0x80040111 || v2` 只要偏离“类不可用 + 输出为空”这一预期就退出。
- **检测逻辑**：这不是检查调试器，而是检查 **COM/API 行为一致性**。沙箱、二进制模拟器或 API hook 框架为了“让样本跑下去”，可能把 `LoadLibrary`/`GetProcAddress` 伪造成成功、让 `DllGetClassObject` 返回 `S_OK` 或其它 HRESULT；样本一旦看到非 `0x80040111` 的返回值，就判断当前不是真实 Windows 环境。反过来，精简/裁剪系统若缺少 `pid.dll`，`LoadLibrary` 失败同样会导致退出。
- **与同类检查的关系**：和“无效句柄调用 `NtIsProcessInJob` 期望固定返回 293”“`NtCompressKey` 期望失败”“时间差/`rdtsc` 校验”属于同一类 **API 返回值指纹**：正常系统的错误码/边界行为是稳定的，模拟环境难以完整复刻。
- **成本与局限**：实现只需两次 `strcpy` + 一次函数指针调用，体积极小；但特征也很明显（模块名 `pid.dll`、函数名 `DllGetClassObject`、常量 `0x80040111`），静态扫描容易命中；真实环境若被补丁/Hook 成同样的返回值也可绕过。

## 触发条件

- Windows 主机，系统目录存在 `pid.dll`（常规 Windows 默认存在）。
- 样本已解密到执行环境检测的阶段，能够调用 `LoadLibraryA`/`GetProcAddress` 并执行 COM 导出。
- 运行环境（沙箱/模拟器/API hook 框架）对 `pid.dll!DllGetClassObject` 的返回值或输出参数与真实系统不一致。
- 分析者未 patch 该检查或 Hook 返回值。

## 利用步骤

1. 在 IDA 字符串窗口搜索 `pid.dll`、`DllGetClassObject`，定位交叉引用与调用点。
2. 确认调用参数：全零 CLSID 缓冲、`riid=0`、输出指针初值为 1；返回值与 `0x80040111` 比较。
3. 动态调试时在 `LoadLibraryA("pid.dll")`、`GetProcAddress(...,"DllGetClassObject")` 与函数指针调用处下断，记录真实返回值与输出指针。
4. 若样本在沙箱中提前退出，把返回值 patch 成 `0x80040111`、输出指针置 0，或直接跳过该分支，继续后续加载。
5. 记录该检查为样本指纹：模块名/函数名/常量三元组可用于 YARA 与家族聚类。

## PoC

原文反编译得到的检测逻辑（仅用于分析/检测，未执行）：

```c
static int is_real_windows(void) {
    char dll[0x20] = {0}, fn[0x20] = {0};
    void *out = (void *)1;          // v2 = 1
    unsigned char clsid[0x20] = {0};// v5 全零
    strcpy(dll, "pid.dll");
    strcpy(fn, "DllGetClassObject");
    HRESULT (__stdcall *p)(void *, const void *, void **) =
        (void *)GetProcAddress(LoadLibraryA(dll), fn);
    if (!p) return 0;               // pid.dll/导出缺失也退出
    HRESULT hr = p(clsid, NULL, &out);
    return hr == 0x80040111 && out == NULL;  // 只有预期结果才继续
}
```

```text
动态验证：
- 真实 Windows：pid.dll!DllGetClassObject(全零 CLSID, NULL, &out) → 0x80040111，out = NULL
- 若沙箱/Hook 返回 S_OK 或其它 HRESULT，或 out 非空 → 样本退出
```

## 变体与关联

- 变体：可换成其它系统 DLL 的 COM 导出（如 `ole32.dll`、`shell32.dll` 的 `DllGetClassObject`）或其它稳定错误码；也可检查 `GetProcAddress` 是否为空、模块基址是否落在预期范围。
- 变体：与无效句柄 API 返回值检查组合（`NtIsProcessInJob`、`NtCompressKey`），形成多探针环境指纹。
- 关联：`[[code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks]]` 记录了同一银狐样本族的环境检测全集（该卡正文未展开本检查，仅在其核对备注中提到 `CLASS_E_CLASSNOTAVAILABLE`）；`[[code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum]]` 是标记文件 + 调试器 + AV 进程组合；`[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]` 是时间/用户名/`DebugPort` 类检查。
- 边界：文章只给出反编译片段与常量，未在沙箱/真实机对比该 API 的实际返回值；`pid.dll` 在不同 Windows 版本/精简系统中的存在性与 COM 注册状态可能不同，检查失败不一定说明是沙箱。

## 检测与防御

- 检测：样本导入/动态解析 `LoadLibraryA("pid.dll")`、`GetProcAddress("DllGetClassObject")`，随后以全零 CLSID 调用并比较 `0x80040111`；静态搜索 `pid.dll` + `DllGetClassObject` + `80040111` 三元组。
- 行为：非 COM 宿主进程加载 `pid.dll` 并调用其 COM 导出，属于少见行为；EDR 可对“加载系统 DLL 后立即以空参数调用 COM 入口”的序列告警。
- 沙箱/模拟器：对 `pid.dll!DllGetClassObject` 返回真实 HRESULT（`0x80040111`）并保持输出为空；不要把所有 API 都伪造成成功。
- 分析对抗：在调用点 patch 返回值或跳过分支；也可在沙箱中预置真实 `pid.dll` 并透传系统调用。
