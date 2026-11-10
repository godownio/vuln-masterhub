---
id: ctf-forensics-png-lsb-zsteg-download-url-openpgp-payload
title: PNG LSB 隐写提取下载 URL 与 OpenPGP 公钥：zsteg 多通道扫描并按大小比对释放载荷
type: scenario
domain: ctf
path: ctf/forensics
technique: png-lsb-zsteg-download-url-openpgp
aliases:
- zsteg PNG 下载 URL
- PNG LSB OpenPGP 公钥
- my.png default.a 载荷比对
- 图片隐写载荷定位
tags:
- ctf
- forensics
- png
- lsb
- steganography
- zsteg
- malware-analysis
- payload-identification
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:06:31+08:00'
  notes: 已对照原文核对；img10 zsteg 的 b1,rgb,lsb,xy URL 与 b3 OpenPGP Public Key、img02/11 大小 4,505KB 均符；gpg 步骤为补充通用解析，原文未演示；未实际下载/导入
---

## 一句话结论

样本释放的 `my.png` 看起来是正常 PNG，但 `zsteg` 在 `b1,rgb,lsb,xy` 通道读出下载 URL（指向 C2 主机下的 `default.a`），在 `b3,rgb,lsb,xy` 识别出 OpenPGP Public Key；按该地址取得的 `default.a` 与样本释放的 `file` 同为 4,505KB，可据此把 PNG 判定为下一阶段载荷的定位/校验信息载体，而不是把完整载荷塞进图片。

## 原理

- **PNG LSB 隐写**：PNG 解码后是逐像素的通道字节（常见 RGB/RGBA），修改每个通道的最低位只改变色值 1/256，人眼不可见；把 ASCII/二进制数据按位铺进低位，就能在图里藏字符串或文件。
- **zsteg 的扫描面**：zsteg 会枚举位平面（b1~b8）、通道顺序（rgb/bgr 等）与扫描顺序（xy/yx），把提取出的位流按字节重组，再用文本/文件签名规则判断内容。因此隐藏时只要与扫描参数一致，就能在某一通道组合中还原。
- **为什么能读出 URL**：URL 以普通的连续字节写入 LSB，zsteg 的 text 规则把可打印字节流识别为文本；原文在 `b1,rgb,lsb,xy` 得到下载地址。其他通道里出现大量重复字符（如 `U`、`DETTE...`）属于填充/噪声，需要按内容筛选。
- **为什么能识别 OpenPGP 公钥**：OpenPGP 公钥有固定的包结构/魔数，zsteg 的 file 规则在 `b3,rgb,lsb,xy` 与 `b3,bgr,lsb,xy` 都命中 `OpenPGP Public Key`；公钥可能用于校验或解密后续载荷、或作为攻击者基础设施标识。
- **大小比对的意义**：PNG 本身只有 645KB，不可能直接容纳 4.5MB 的 `default.a`，所以图片里藏的应是定位信息；下载得到的文件与释放的 `file` 大小同为 4,505KB，说明两者很可能是同一载荷（严格确认应再比对 SHA256）。
- **为什么攻击者这样做**：PNG 可正常渲染、静态文件扫描不易报警；把下载 URL 与公钥放进图片，样本只需携带小体积图片，下一阶段从网络获取，便于更换载荷。

## 触发条件

- 已取得样本释放或投递的 PNG（例如恶意样本释放的 `my.png`），且图片未经有损重编码/缩放，LSB 未被破坏。
- 具备 zsteg（Ruby）或等价的 LSB 提取脚本；知道或愿意枚举通道/位平面/扫描顺序。
- 有可对照的释放文件或样本本体，用于大小/哈希比对。
- 若需实际访问 URL，应在隔离网络中进行；生产环境只把地址作为 IOC，不直接连接。

## 利用步骤

1. 确认文件是合法 PNG（签名、IHDR），记录文件大小与哈希。
2. 运行 `zsteg <file>.png`，逐条检查 `b1..b8` × `rgb/bgr` × `xy/yx` 的输出：文本行找 URL/路径，file 行找 `OpenPGP Public Key` 等签名。
3. 对候选通道可用 `zsteg -E '<bits>,<channels>,lsb,<order>' <file>.png > out.bin` 导出原始字节；文本类结果可直接截取。
4. 在隔离环境中按 URL 获取文件（或从样本释放目录取得 `file`），比较大小；进一步计算 SHA256 确认是否同一载荷。
5. 用 `gpg --list-packets`/`gpg --import` 离线解析导出的 OpenPGP 公钥，记录指纹作为 IOC。
6. 将 URL、公钥指纹、载荷哈希整理为 IOC；不要在生产网络访问 C2。

## PoC

```bash
zsteg '/path/to/my.png'
# b1,rgb,lsb,xy  .. text: "http://<C2-IP>/<id>/default.a"
# b3,rgb,lsb,xy  .. file: OpenPGP Public Key
# b3,bgr,lsb,xy  .. file: OpenPGP Public Key
```

```bash
# 导出候选 LSB 字节（仅用于查看图片内隐藏的元数据，不等于下一阶段载荷）
zsteg -E 'b1,rgb,lsb,xy' my.png > embedded.bin

# 将按 URL 下载的 default.a 与样本释放的 file 比对
ls -l /path/to/default.a /path/to/file   # 原文两者均为 4,505 KB
sha256sum /path/to/default.a /path/to/file
```

> 说明：原文未给出样本哈希；下载地址与公钥为原文截图中的 IOC，地址已按入库规则脱敏，未在本机访问或导入。

## 变体与关联

- 扫描顺序变体：[[ctf-forensics-png-lsb-column-major-scan-order]] 覆盖 xy 无结果时改用 yx/列优先，并说明短载荷的判定方法。
- 载荷执行型：[[pentest-initial-access-png-lsb-steganography-fileless-shellcode-loader]] 把 shellcode 直接写入 LSB 并在内存执行；本卡的 LSB 隐藏的是下载 URL 与公钥，用于定位/校验下一阶段载荷，二者用途不同。
- 同篇的载荷配置提取见 [[code-analysis-reverse-windows-pupy-frozen-config-decoder]]：本卡负责从 PNG 找到 `default.a`/释放文件，另一卡从该文件中解出 C2。
- 其他 PNG 隐写：`ctf/forensics` 下的 PNG 尾部附加数据、DCT/QIM、多通道二维码等卡可作为通道/编码变体参考。
- 边界：图片被有损压缩、缩放或重新编码会破坏 LSB；随机位流可能产生文本误报，需要结合通道、大小与哈希确认；大小相同不等于同一文件，最终以哈希为准。

## 检测与防御

- 检测：对图片做 LSB 位平面扫描与 `zsteg` 类分析，关注 b1/b3 等低位中的 URL、OpenPGP 公钥、PE/ELF 头等异常；检查样本是否释放 PNG 并伴随外联下载。
- 防御：对邮件/下载附件图片做隐写检测；限制终端对图片内嵌 URL 的自动访问；封禁提取出的 C2 地址与公钥指纹；对下载文件做哈希与沙箱分析。
- 响应：隔离主机，提取 PNG、`default.a` 与释放文件；离线比对哈希；封禁 IOC；继续分析下一阶段载荷。
- 该场景仅用于授权取证/CTF 分析，不要访问未知 C2 或导入不可信公钥。
