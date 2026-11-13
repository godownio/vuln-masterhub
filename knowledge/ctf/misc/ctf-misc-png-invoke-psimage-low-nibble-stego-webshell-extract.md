---
id: ctf-misc-png-invoke-psimage-low-nibble-stego-webshell-extract
title: Invoke-PSImage 低 4 位像素隐写识别与提取：PNG 每像素两通道低半字节藏 PowerShell WebShell，按行重组还原
type: scenario
domain: ctf
path: ctf/misc
technique: png-invoke-psimage-low-nibble-stego-powershell-webshell-extract
aliases:
- Invoke-PSImage
- PNG 低 4 位隐写
- 像素隐写
- 图片藏 webshell
- Stegsolve 低位分析
- peewpw Invoke-PSImage
- PowerShell 脚本藏图
tags:
- ctf
- misc
- stego
- png
- lsb
- invoke-psimage
- powershell
- webshell
- stegsolve
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V629
  verified_at: '2026-11-12T23:31:31+08:00'
  notes: 已对照 content.md 与全部 6 张截图核对：图01-04 为 Stegsolve Green plane 3/2/1/0，图05 Extract Preview（Row/MSB、位面勾选、hex dump 无明文特征），图06 CyberChef From Base64+XOR 35 输出可见 User-Agent MSIE 10.0 MALCJS 与 C2 IP 145.142.212.3，均与卡一致；Invoke-PSImage 编码逻辑（payload 字节高 4 位+低 4 位分写两通道、第三通道随机、输出无损 PNG）与原文 PowerShell 片段一致；原文提取脚本取 pixels[1](G) 低半字节 | pixels[2](B) 高半字节，卡内 PoC 等价。验证中修正一处表述：原文循环按 3 字节/像素索引（24bpp BGR 内存序），卡内原写“32bpp BGRA”不准确，已改为 24bpp BGR（结论 B=高4位、G=低4位、R=随机 不变，库内与 staging 草稿已同步修正）。skipped 的 PowerShell 加载器经比对既有卡 pentest-c2-vbs-powershell-obfuscated-delegate-shellcode-loader：同为 FromBase64String+XOR、UnsafeNativeMethods GetProcAddress/GetModuleHandle、Reflection.Emit MulticastDelegate、GetDelegateForFunctionPointer、VirtualAlloc 执行 shellcode，仅混淆层与 XOR 密钥不同，确为同 sink，不单独建卡成立（RunAs32 为后利用细节，未丢失关键链）。未执行附件样本与提取脚本，仅静态核对。CTF/工具隐写格式无受影响版本，未设 affected_versions。
---

## 一句话结论

Invoke-PSImage 把 PowerShell 脚本按字节拆成高/低 4 位，写入 PNG 每个像素两路颜色通道的低 4 位（另一路低 4 位用随机数填充），输出必须是无损 PNG；遇到可疑图片时用 Stegsolve 观察各通道低位/位面（多呈噪声），再按行读 G 通道低 4 位作低半字节、B 通道低 4 位作高半字节重组成字节，即可还原隐藏的 PowerShell 恶意脚本。本案例（湖南省赛题 `PNG.exe.zip` 内的 `flag.png`）还原出的是一个 base64 + XOR 35 的 shellcode 加载器，解码后可见 C2 IP `145.142.212.3`。

## 原理

- **Invoke-PSImage 的编码方式**：工具用 `System.Drawing.Bitmap` 读图并 `LockBits` 把像素拷进 `$rgbValues` 字节数组；原文循环按 `$rgbValues.Length/3` 与 `$counter*3(+1/+2)` 索引，即 3 字节/像素（GDI+ 24bpp 像素在内存中按 **BGR** 排列；32bpp 则为 BGRA，首个字节同为 B 通道），因此循环里 `$rgbValues[$counter*3]` 实际是 **B 通道**，写入 payload 字节的高 4 位（`[math]::Floor($payload[$counter]/16)`）；`$rgbValues[$counter*3+1]` 是 **G 通道**，写入低 4 位（`$payload[$counter] -band 0x0f`）；`$rgbValues[$counter*3+2]` 是 **R 通道**，写入随机 4 位填充。每个 payload 字节占用一个像素的两路 4 位，容量远大于“每通道只改最低 1 位”的常规 LSB。
- **写入只动低 4 位**：`orig & 0xf0 | nibble` 保留高 4 位、替换低 4 位；因此保存为 PNG（无损）后数据不会因压缩而丢失，但图像质量会下降，与原图对比时可见差异。
- **README 自述**：工具说明“the least significant 4 bits of 2 color values (2 of RGB) in each pixel”，与上述实现一致；输出强制 PNG 就是因为需要无损。
- **提取为什么有效**：逐像素按行序读 G、B 两通道低 4 位即可重组原始字节——`byte = (G & 0x0f) | ((B & 0x0f) << 4)`。若按视觉 RGB 顺序误取 R/G 会得到错误数据，这是最容易踩的坑；用 Stegsolve 逐通道查看低位/位面可以确认哪两路存在噪声（R 通道低 4 位为随机填充，看起来也有噪声，需以工具源码的 BGR 内存顺序为准）。
- **本案例链路**：`flag.png` 提取出的 PowerShell 脚本先用 `[Convert]::FromBase64String` 解出一大段字节、逐字节 XOR 35（0x23）得到 shellcode；脚本用 `AppDomain.GetAssemblies()` 找到 `System.dll` 的 `Microsoft.Win32.UnsafeNativeMethods` 反射取 `GetProcAddress`/`GetModuleHandle`，用 `Reflection.Emit` 定义委托类型，`Marshal.GetDelegateForFunctionPointer` 调用 `VirtualAlloc(0x3000,0x40)` + `Marshal.Copy` 写入并执行 shellcode；64 位系统用 `start-job -RunAs32` 强制 32 位执行。解码后的 shellcode 配置可见 `User-Agent: ... MSIE 10.0 ... MALCJS` 与 C2 IP `145.142.212.3`（端口可猜测 80/8080/443）。
- **与常规位面隐写的区别**：这里不是取某个通道的连续 1 位平面，而是“每像素两通道各 4 位”的半字节打包，数据密度高、Stegsolve 位面视图只能看到噪声，需要专门按半字节重组；JPEG 等有损格式会破坏低 4 位，故只适用于 PNG 等无损载体。

## 触发条件

- 拿到可疑 PNG（webshell 上传目录、CTF 题目附件、钓鱼邮件/压缩包中的图片），且文件确实为无损 PNG。
- 载荷生成端使用 Invoke-PSImage（或按同款“两通道各低 4 位”规则自实现）嵌入 PowerShell 脚本。
- 分析者可读取像素（PIL、Stegsolve、zsteg 等）并写重组脚本。

## 分析步骤

1. 识别载体：`file`/十六进制头确认是 PNG；注意 `.png.exe.zip` 这类双后缀或压缩包内图片。
2. Stegsolve 打开图片，查看 Bit Planes（如 Green/Blue 的 3..0 位）与 Extract Preview（Extract By Row、MSB First），观察噪声分布，确认低 4 位有数据。
3. 按 Invoke-PSImage 规则提取：遍历像素，`byte = (pixel.G & 0x0f) | ((pixel.B & 0x0f) << 4)`，按行优先写出二进制。
4. 检查输出：应是明文 PowerShell（或可继续解码的文本）；若开头是 `Set-StrictMode`/函数定义等，即得到隐藏脚本。
5. 分析脚本：提取 base64 串，按同一脚本里的 XOR 密钥（本例 35）解码，得到 shellcode；沙箱/静态提取其中的 C2 地址与 User-Agent 等配置。
6. 若第 3 步结果乱码：核对通道顺序（试 R/G、G/B、R/B 组合）与位序（高低半字节是否互换），或改用 Stegsolve 手工提取对照。

## PoC

按行提取 G（低半字节）与 B（高半字节）的 Python（原文脚本，正确对应工具 24bpp BGR 内存顺序）：

```python
from PIL import Image

def extract_invoke_psimage(image_path):
    img = Image.open(image_path)
    width, height = img.size
    out = bytearray()
    for y in range(height):
        for x in range(width):
            r, g, b = img.getpixel((x, y))[:3]
            out.append((g & 0x0F) | ((b & 0x0F) << 4))  # G 低4位=低半字节，B 低4位=高半字节
    return bytes(out)

data = extract_invoke_psimage("flag.png")
open("payload.bin", "wb").write(data)
```

若输出的开头是 PowerShell 脚本，继续按脚本中的 `FromBase64String` + XOR 密钥解码 shellcode（本例 XOR 35）。

## 变体与关联

- 变体：工具可把载荷嵌入已有图片（质量下降但更隐蔽）；自实现版本可能交换通道或位序，提取时逐一尝试 G/B、B/G、R/G 组合即可。
- 同思路图片藏载荷：[[ctf-misc-png-bitplane-zip-base85-shellcode-c2]]（Stegsolve 取 Red 7–1 位面得到 zip → Base85 shellcode）、[[ctf-forensics-png-lsb-embedded-fat12-disk-testdisk]]（zsteg 位平面提取 FAT12 镜像）、[[pentest-initial-access-jpg-marker-stego-vbs-nanocore-loader]]（JPG 标记段 Base64 + Assembly.Load）、[[code-analysis-reverse-windows-dotnet-bitmap-stego-multistage-reflective-load]]（位图隐写多阶段反射加载）。
- 提取出的 PowerShell 加载器属于“反射 P/Invoke + Reflection.Emit 委托 + VirtualAlloc”家族，同类实现见 [[pentest-c2-vbs-powershell-obfuscated-delegate-shellcode-loader]]（VBS→PowerShell 多阶段混淆 + delegate 调 VirtualAlloc）。
- 关联：[[code-analysis-reverse-obfuscation-powershell-bytearray-xor-iex-multistage]]（PowerShell 字节数组 XOR + iex 多阶段）。

## 检测与防御

- 检测：对上传目录/附件中的 PNG 做低 4 位统计与提取（正常图片低 4 位近似均匀随机，嵌入数据后按半字节重组会出现明文脚本特征）；关注 `PNG.exe.zip` 等双后缀与图片中隐藏的 PowerShell 关键字（`Set-StrictMode`、`FromBase64String`、`VirtualAlloc`）；Stegsolve/zsteg 先行筛查。
- 防御：上传接口对图片做重编码（有损/重采样可破坏隐写）；禁止从图片解析/执行任何脚本；监控 Web 服务进程派生 `powershell.exe` 的行为； PowerShell 启用约束语言模式、AMSI 与脚本块日志。
- 取证：提取出的 payload 与 C2 IOC（本例 `145.142.212.3`）用于阻断与关联分析。
