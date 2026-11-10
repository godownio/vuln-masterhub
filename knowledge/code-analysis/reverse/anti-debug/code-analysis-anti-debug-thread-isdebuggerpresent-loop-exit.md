---
id: code-analysis-anti-debug-thread-isdebuggerpresent-loop-exit
title: 独立线程循环调用 IsDebuggerPresent 的反调试：检测到调试器即打印并 exit，需先 patch 再动态调试
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: thread-isdebuggerpresent-loop-exit
aliases:
- 线程反调试
- IsDebuggerPresent 循环检测
- 反调试线程绕过
- debuggerpresent 检测退出
tags:
- reverse
- anti-debug
- windows
- threading
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-28
  verified_at: '2026-11-08T15:02:25+08:00'
  notes: 已对照原文核对：图16 CreateThread+StartAddress 951240、图17 while(!IsDebuggerPresent())+exit(0) 证实；bp 变换与原文脚本一致
---

## 一句话结论

程序另起一个独立线程，循环检查 `IsDebuggerPresent()`，一旦返回真立即打印提示并 `exit(0)`；由于检测跑在主线程之外的线程里，单步在主线程下断不易察觉，逆向时需先定位该线程函数并 patch 掉检测分支（或改 exit 为空），再进行动态调试还原后续算法。

## 原理

- `IsDebuggerPresent` 读取 TEB 的 `BeingDebugged` 标志，成本极低，适合放进高频率循环；
- 把检测放入 `CreateThread(0,0,StartAddress,0,0,0)` 创建的线程，与主逻辑并行执行，调试器断在主线程时检测线程仍在轮询，形成「一动就退」的效果；
- 线程函数体形如 `while(!IsDebuggerPresent()); sub_xxx("debug!\n"); exit(0)`——绕过点就是让 `IsDebuggerPresent` 恒为假或让 `exit` 变成空操作。

## 触发条件

- 逆向分析带多线程反调试的二进制，需动态调试观察算法（本题主逻辑为多线程执行下的字节变换 `(num<<6)^(num>>2)` 后异或 0x23、加 100）。

## 利用步骤

1. 静态扫描导入表/字符串定位 `IsDebuggerPresent` 与 `exit` 的交叉引用，找到检测线程函数（如 `sub_951240`）。
2. 用调试器跑到线程函数，把 `while(!IsDebuggerPresent())` 的条件恒真/恒假化（nop 掉 jcc 或 patch 函数开头直接 ret），或将 `exit` 调用 nop 掉。
3. 继续动态调试主逻辑：观察每轮变换加的常量与异或值，去除花指令后还原出 `(num<<6) ^ (num>>2) & 0xff`、`^0x23`、`+100` 的逆变换脚本，逐字节爆破出明文。

## PoC

```python
def bp(num):
    num = ((num << 6) ^ (num >> 2)) & 0xff
    num ^= 0x23
    return (num + 100) & 0xff
# 对密文逐字节在 printable 集合内穷举 bp(char) 匹配
```

## 变体与关联

- 同线程内高频检测、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess(ProcessDebugPort)`、TEB 手工读取等均为同族手法；
- 与 TLS 回调反调试、异常处理反调试可叠加，需逐层 patch。

## 检测与防御

- 作为防护方：该手法可直接用于自研程序防调试，注意同时校验 PEB BeingDebugged 与 NtGlobalFlag，防止单点 patch；
- 作为分析方：x64dbg 可用 ScyllaHide 插件自动隐藏 BeingDebugged 标志，免逐个 patch。
