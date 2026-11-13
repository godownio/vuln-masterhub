---
id: crypto-ecc-recover-plaintext-from-ec-elgamal-known-k
title: EC ElGamal 私钥 k 泄露：m=c1−k·c2 解出明文点，再按坐标分量做域除法恢复两段 flag
type: scenario
domain: crypto
path: crypto/ecc
technique: ec-elgamal-known-k-decrypt-coordinate-division
aliases:
- ECC ElGamal 解密
- 已知私钥 k 解密
- c1-k*c2
- HGAME 2022 ECC
- 坐标分量整除恢复明文
tags:
- crypto
- ecc
- elgamal
- decryption
- sage
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V526
  verified_at: '2026-11-11T15:14:34+08:00'
  notes: 已对照原文与全部5张图核对，并用纯Python自写仿射点加/倍点独立复算：先用原文E29(4,20)示例校验实现（25G=(14,6)、6G=(5,7)、C1=(6,12)、C2=(5,7)、解密得(3,28)，37阶一致）；对HGAME参数计算 m=c1-k*c2 后，按GF(p)域除法 cl*m0^{-1} mod p 与 cr*m1^{-1} mod p 还原出 hgame{Ecc$is!sO@HaRd}，与原文输出一致；验证了普通整数floor除法因乘积在GF(p)内取模而不整除，故已将卡片『整数整除』修正为『域除法（乘坐标模逆元）』，并同步标题、原理、步骤与PoC（knowledge卡与staging草稿）。原文参数b与Sage打印的E系数相差恰好p（模p一致），无矛盾。dedup候选均related非同链；dup-scan无本卡pair。未验证点：Sage脚本本身未执行，PoC现给出显式逆元写法。
---

## 一句话结论

在 EC ElGamal 加密 `c1=m+rK`、`c2=rG`、`K=kG` 中，只要题目泄露了私钥 `k`（或等价地给出了 `k`），直接计算 `m=c1−k·c2` 即得明文点；若明文被拆成 `cipher_left=s2n(flag前半)·m[0]`、`cipher_right=s2n(flag后半)·m[1]`（在 `GF(p)` 内取模），再做域除法（乘坐标的模逆元）即可恢复两段字节并拼接出 flag。

## 原理

- EC ElGamal 加密：私钥 `k`、公钥 `K=kG`；发送方选随机数 `r`，密文 `c1=m+rK`、`c2=rG`；接收方计算 `c1−k·c2 = m+rK−k(rG) = m+r(kG)−k(rG) = m`。安全性依赖 `k` 保密与 ECDLP 困难。
- 题目直接打印 `k`（或通过其他漏洞泄露）时，ECDLP 被完全绕过，一次点运算即可恢复明文点 `m`。
- 明文编码方式：把 flag 从中间切两半，分别 `s2n`（bytes→int）后与明文点 `m` 的 x、y 坐标相乘。注意 `m[0]`/`m[1]` 是 `GF(p)` 元素，乘积在有限域内取模后才是打印出的 `cipher_left/cipher_right`；因此恢复时要按坐标做**域除法**（`cipher_left * m[0]^{-1} mod p`，`cipher_right * m[1]^{-1} mod p`），结果恰为小于 p 的 `s2n` 值，再 `long_to_bytes` 拼接。用普通整数 floor 除法会因模约减而不整除（本卡验证时用等价 Python 纯实现复算：域除法还原出 `hgame{Ecc$is!sO@HaRd}`，与原文一致）。
- 注意点运算要在 Sage 的 `EllipticCurve(GF(p),[a,b])` 上构造点后做减法与标量乘，不能直接对坐标做整数运算；`c1`、`c2` 的坐标来自输出，需要 `E([x,y])` 还原为曲线点。

## 触发条件

- 题目给出椭圆曲线参数 `p,a,b`、密文点 `c1,c2`、`cipher_left,cipher_right`，并且泄露私钥 `k`（或 `K` 与 `k` 同时给出）。
- 曲线定义在素域 `GF(p)` 上，点可被 Sage 正常构造。
- 明文按坐标分量乘法编码（`flag` 两半分别乘 `m[0]`、`m[1]`）。
- 有 SageMath 环境。

## 利用步骤

1. 用 `E = EllipticCurve(GF(p),[a,b])` 建曲线，`E([x,y])` 还原 `c1`、`c2` 为曲线点。
2. 计算 `m = c1 - k*c2`，得到明文点。
3. 分别做域除法并转 `int`：`ml = int(cipher_left * m[0]^-1)`、`mr = int(cipher_right * m[1]^-1)`（`m[0]^-1` 为 GF(p) 逆元；若用普通整数 `//` 会得到错误结果）。
4. `long_to_bytes(ml) + long_to_bytes(mr)` 拼接并输出 flag。
5. 若除法结果不可读，检查是否给出的 `k` 对应 `K=kG`、坐标顺序是否颠倒、或明文切分点是否按字节长度而非字符。

## PoC

```python
# SageMath
from Crypto.Util.number import long_to_bytes
p = 74997021559434065975272431626618720725838473091721936616560359000648651891507
a = 61739043730332859978236469007948666997510544212362386629062032094925353519657
b = 87821782818477817609882526316479721490919815013668096771992360002467657827319
k = 93653874272176107584459982058527081604083871182797816204772644509623271061231
cipher_left  = 68208062402162616009217039034331142786282678107650228761709584478779998734710
cipher_right = 27453988545002384546706933590432585006240439443312571008791835203660152890619
E = EllipticCurve(GF(p), [a, b])
c1 = E([14455613666211899576018835165132438102011988264607146511938249744871964946084,
        25506582570581289714612640493258299813803157561796247330693768146763035791942])
c2 = E([37554871162619456709183509122673929636457622251880199235054734523782483869931,
        71392055540616736539267960989304287083629288530398474590782366384873814477806])
m = c1 - k * c2
# cipher_left/right 是 s2n(半段flag)*m[坐标] 在 GF(p) 中取模后的值，须做域除法
ml = int(cipher_left * m[0]^-1)
mr = int(cipher_right * m[1]^-1)
print(long_to_bytes(ml) + long_to_bytes(mr))
```

本卡验证时已用等价 Python 纯实现（自写仿射点加/倍点）复算：`m=c1−k·c2` 后经 GF(p) 域除法还原出 `hgame{Ecc$is!sO@HaRd}`，与原文输出一致；上述 Sage 脚本本身未在本机执行。原文 solve 脚本中的 `cipher_left//m[0]` 在 Sage 里对 GF(p) 元素即域除法（作者也注明结果需 `int()` 转换），与显式乘逆元等价。

## 变体与关联

- 变体：若 `k` 未泄露但 `r` 复用/可预测，可先恢复 `k` 再解密；若只泄露 `k` 的高位，见 ECDH/ECDSA 的 HNP 类卡。
- 变体：明文编码可能是 `m + s2n(flag)`（加法）而非分量乘法，此时直接 `m - s2n(...)` 或对坐标做减法恢复。
- 关联：[[crypto-ecc-recover-curve-parameter-a-from-g-and-2g]]（同篇第一题的参数反解）、[[crypto-ecc-ecdh-small-nonce-brute-shared-point-key]]（小 nonce 恢复共享点）、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（nonce 复用恢复私钥）。

## 检测与防御

- 实战侧：绝不能在日志/响应中输出私钥 `k`；EC ElGamal 需配合安全随机数 `r` 与经过验证的曲线参数。
- 出题/测评侧：泄露 `k` 等同于明文直接公开；若需考察解密流程，应让选手通过 ECDLP 或侧信道恢复 `k`，而不是打印。
- 检测：输出字段中出现与 `K=kG` 匹配的标量、或同时给出 `k` 与密文点时，先尝试直接解密。
