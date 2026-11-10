---
id: dotnet-bitmap-stego-multistage-reflective-load
title: .NET WinForms 资源 Bitmap 隐写提取字节并多阶段反射加载（小马拉大马）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: stego-loader
tags:
- steganography
- loader
- dotnet
- reflective-loading
severity: medium
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/code-analysis/reverse/windows/dotnet-bitmap-stego-multistage-reflective-load/
draft: false
kb_aliases:
- Bitmap 隐写加载器
- 小马拉大马反射加载
---

## 一句话结论

把下一阶段 .NET 程序集逐像素隐写进资源中的 Bitmap，WinForms 窗体初始化时用 `GetPixel` 按 R/G/B 提取字节、`Assembly.Load` 内存加载并 `LateBinding.LateGet` 动态调用其入口，多层嵌套实现"小马拉大马"式无文件落盘的多阶段加载。

## 原理

隐写把 PE 字节拆进图片像素的颜色通道，图片本身是合法位图，杀软对资源做静态特征扫描时看不到任何可执行内容；提取逻辑以 `componentResourceManager.GetObject("sv") as Bitmap` 取图，按 `maximumBytes` 上限逐像素 `GetPixel` 收集 R/G/B 三通道字节还原原始流。随后 `LateBinding.LateGet(AppDomain.CurrentDomain, null, GetString("az")/*返回"Load"*/, ...)` 绕过对 `Assembly.Load` 的直接调用引用，`Assembly.GetTypes()[0]` 定位入口类型并 `Activator.CreateInstance` 实例化执行。第二阶段 dll 内再用同样手法从自己的资源读出第三阶段数据，动态获取类名/方法名后 `Invoke`，链条上每一环都不落盘、方法名随机化（如 FgNZFlgdye）且整体混淆，极大增加静态检测与人工分析成本。

## 触发条件

- 目标运行 .NET Framework 且用户执行伪装的 WinForms 程序（如伪装计算器/订单查看器）；
- 资源中的隐写 Bitmap 与提取逻辑随样本携带，无外部依赖。

## 利用步骤

1. 伪装成正常工具（如 New Purchase Order.exe/QuantumCalc Pro）诱导执行；
2. `Form1.InitializeComponent` 中读取资源 Bitmap，GetPixel 逐像素提取字节流；
3. 反射调用 `AppDomain.CurrentDomain.Load` 加载第二阶段 dll 并实例化其入口类；
4. 第二阶段再次从自身资源读隐写 Bitmap（先做尺寸/颜色还原），内存 dump 出第三阶段；
5. 动态解析指定类与方法名（Invoke 调用），进入实际恶意逻辑（Defender 排除、复制自身、计划任务、进程注入、窃密）。

## PoC

```csharp
// 隐写提取核心（第一/二阶段同构）
Bitmap bmp = componentResourceManager.GetObject("sv") as Bitmap;
List<byte> buf = new List<byte>();
for (int x = 0; x < bmp.Width && buf.Count < max; x++)
    for (int y = 0; y < bmp.Height && buf.Count < max; y++) {
        Color p = bmp.GetPixel(x, y);
        buf.Add(p.R); buf.Add(p.G); buf.Add(p.B);
    }
Assembly asm = (Assembly)LateBinding.LateGet(AppDomain.CurrentDomain, null,
    componentResourceManager.GetString("az") /* "Load" */, new object[]{ buf.ToArray() }, null, null);
object inst = Activator.CreateInstance(asm.GetTypes()[0]);
```

## 变体与关联

- 变体：隐写通道可换成 alpha 通道、LSB、PNG 附加数据、音频等；提取前常对 Bitmap 尺寸/颜色做变换（RestoreOriginalBitmap）对抗直接资源导出；
- 与动态 API 解析、字符串加密、控制流混淆组合是 .NET 恶意软件常见免杀加载链；
- 该链的最终阶段常落到进程注入与系统持久化（见傀儡进程注入、Defender 排除项等卡）。

## 检测与防御

- 对 .NET 程序集运行时 `Assembly.Load(byte[])` 的调用做内存扫描（而非仅磁盘特征）；
- 检测可疑组合：GUI 程序初始化阶段即出现反射加载、资源含大体积 Bitmap 且执行 GetPixel 循环；
- 邮件网关/下载侧拦截伪装文档类可执行文件（订单/发票诱导）。
