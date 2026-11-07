---
id: ctf-reverse-prime-constrained-time-three-prime-rsa
title: 素数约束时间 + 三素数 RSA 变体：用目标自带 GMP 枚举时间并解密两段密文
type: scenario
domain: ctf
path: ctf/reverse
technique: prime-constrained-time-three-prime-rsa
aliases:
- Find My Time
- 三素数 RSA
- 素数时间校验
- GMP 素数枚举
- Qt GUI 时间门
tags:
- ctf
- reverse
- rsa
- gmp
- prime
- qt
- ctypes
- time
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:47:13+08:00'
  notes: 已对照原文 Find My Time 及图57/59/61 核对：Qt QTimer 回调、gmtime/UTC、month∈{2,3,5,7,11} 且 %02d 后仅 11 无 0、day/hour/min/sec 素数、YYYYMMDD/hhmmss/t/DT/P1/P2 素数、三素数 RSA e=t，以及两个命中时间与 flag 均一致。未验证点：未用目标 libgmp-10.dll 实跑枚举。
---

## 一句话结论

程序要求“当前 UTC 时间”同时满足一串素数条件：月、日、时、分、秒的数值是素数，`YYYYMMDD`、`hhmmss`、Unix 秒 `t`、14 位拼接数 `DT`、`DT||t`、`t||DT` 全部是素数，且 `DT` 的十进制表示不含 `0`。满足后程序用 `DT`、`P1=DT||t`、`P2=t||DT` 作为三个素数构造 RSA（`e=t`）解密两段密文。由于月份必须 `11`、日/时/分/秒只能取两位素数，搜索空间很小；用目标自带的 `libgmp-10.dll` 做素性测试，枚举出两个合法时间即可恢复 flag。

## 原理

- **时间门**：Qt 窗口的 `QTimer::timeout` 槽函数把当前 UTC 时间交给校验函数；`gmtime` 语义下年/月/日/时/分/秒都是 UTC，不能用本地时区。
- **约束链**：
  - `month ∈ {2,3,5,7,11}`；
  - `day`、`hour`、`minute`、`second` 的数值均为素数；
  - `YYYYMMDD` 为素数；
  - `hhmmss` 为素数；
  - `t`（Unix 秒）为素数且 `t > 1`；
  - `DT = sprintf("%04d%02d%02d%02d%02d%02d", y, m, d, h, mi, s)` 为素数；
  - `DT` 的十进制字符串中不能出现字符 `'0'`；
  - `P1 = int(str(DT) + str(t))`、`P2 = int(str(t) + str(DT))` 均为素数。
- **月份为什么只剩 11**：月份按 `%02d` 输出，2/3/5/7 会变成 `02/03/05/07`，全部含 `'0'`；而 `DT` 不允许含 `'0'`，所以只剩 `11`（两位数且不含 0）。
- **搜索空间**：日只能取 `{11,13,17,19,23,29}`；时取 `{11,13,17,19,23}`；分/秒取两位素数 `{11..59 中的素数}`；年份 1970..9999 且十进制不含 `0`。先预筛 `hhmmss` 为素数的组合，再逐时间做其余素性测试，实际候选量很小。
- **三素数 RSA**：`n = DT * P1 * P2`，`e = t`，`phi = (DT-1)(P1-1)(P2-1)`，`d = e^{-1} mod phi`，`m = c^d mod n`。三个因子都是大素数，RSA 的安全性与普通两素数 RSA 同源（难在分解 n）；这里的“三素数”只是构造方式，不是弱点本身。
- **两段密文**：程序对两个密文大整数分别解密，得到两段 ASCII，拼接为最终 flag。每个合法时间对应一组 `(n, d)`，用错时间解密会得到不可打印的随机字节，因此“可打印 ASCII”就是筛选条件。
- **GMP 调用**：静态链接/动态加载的 `libgmp-10.dll` 导出 `__gmpz_probab_prime_p`、`__gmpz_powm`、`__gmpz_invert`；可以直接用 `ctypes` 按 `_Mpz {int alloc; int size; uint64_t *d;}` 的布局调用，避免自己实现大整数素性测试。

## 触发条件

- 目标是 Qt/GMP 程序，导入 `__gmpz_probab_prime_p`、`__gmpz_powm`、`__gmpz_invert` 等符号。
- 校验逻辑以系统时间为输入，并包含多个素数/日期格式约束。
- 程序中存在大整数密文常量，以及 `n/e/phi/d` 的构造流程。
- 时间约束把候选压缩到可枚举范围（年份、月份、日、时、分、秒的取值都受限）。

## 利用步骤

1. 通过 GMP 导入函数的 xref 定位校验函数；结合 Qt 的 `QTimer::timeout`/`QObject::connect` 找到定时回调。
2. 还原 `check(t)` 的全部条件，确认使用 `gmtime`（UTC）而不是本地时间，确认 `DT` 的 `%04d%02d%02d%02d%02d%02d` 格式和“不含 0”规则。
3. 枚举候选：月份固定 11；日、时、分、秒按两位素数集合枚举；年份跳过含 `0` 的值；先筛 `hhmmss` 素数。
4. 用 `ctypes` 加载目标目录的 `libgmp-10.dll`，对每个候选调用 `__gmpz_probab_prime_p(n, 30)` 依次验证 `t`、`YYYYMMDD`、`hhmmss`、`DT`、`P1`、`P2`。
5. 对通过的时间计算 `phi`、`d`、`n`；用 `pow(c, d, n)` 解密两个密文，按大端/小端转字节并过滤不可打印结果。
6. 把两段 ASCII 拼接得到 flag；示例命中时间为 `3583-11-11 11:23:31Z` 与 `9923-11-13 23:29:19Z`。

## PoC

```python
import calendar, ctypes, os
from ctypes import POINTER, Structure, byref, c_char_p, c_int, c_ulonglong
from datetime import datetime, timezone

class Mpz(Structure):
    _fields_ = [("alloc", c_int), ("size", c_int), ("d", POINTER(c_ulonglong))]

class Gmp:
    def __init__(self, dll):
        self.lib = ctypes.CDLL(dll)
        self.lib.__gmpz_init.argtypes = [POINTER(Mpz)]
        self.lib.__gmpz_set_str.argtypes = [POINTER(Mpz), c_char_p, c_int]
        self.lib.__gmpz_probab_prime_p.argtypes = [POINTER(Mpz), c_int]
        self.z = Mpz(); self.lib.__gmpz_init(byref(self.z))
    def is_prime(self, n, reps=30):
        if n < 2:
            return False
        self.lib.__gmpz_set_str(byref(self.z), str(n).encode(), 10)
        return self.lib.__gmpz_probab_prime_p(byref(self.z), reps) > 0

gmp = Gmp(os.path.join(os.path.dirname(__file__), "libgmp-10.dll"))
days   = [11, 13, 17, 19, 23, 29]
hours  = [11, 13, 17, 19, 23]
minsec = [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59]

hhmmss_list = []
for h in hours:
    for m in minsec:
        for s in minsec:
            v = h * 10000 + m * 100 + s
            if gmp.is_prime(v):
                hhmmss_list.append((h, m, s, v))

for year in range(1970, 10000):
    if "0" in str(year):
        continue
    for day in days:
        ymd = year * 10000 + 11 * 100 + day
        if not gmp.is_prime(ymd):
            continue
        base = calendar.timegm(datetime(year, 11, day, tzinfo=timezone.utc).utctimetuple())
        for h, m, s, hhmmss in hhmmss_list:
            DT = int(f"{year:04d}11{day:02d}{h:02d}{m:02d}{s:02d}")
            if "0" in str(DT) or not gmp.is_prime(DT):
                continue
            t = base + h * 3600 + m * 60 + s
            if not gmp.is_prime(t):
                continue
            P1 = int(str(DT) + str(t))
            P2 = int(str(t) + str(DT))
            if not (gmp.is_prime(P1) and gmp.is_prime(P2)):
                continue
            phi = (DT - 1) * (P1 - 1) * (P2 - 1)
            try:
                d = pow(t, -1, phi)
            except ValueError:
                continue
            n = DT * P1 * P2
            print(datetime.fromtimestamp(t, timezone.utc), t, n, d)
```

拿到 `(n, d)` 后对两段密文执行：

```python
c1 = 422698873081437624518382059552318235172264293390171053488808121
c2 = 206134179439411414927415781485521487054746196930762801924142747145
# 对命中的时间分别计算 n/d 后：
m = pow(c, d, n)
raw = m.to_bytes((m.bit_length() + 7) // 8, "big").replace(b"\x00", b"")
print(raw)
```

示例结果：`3583-11-11 11:23:31Z` 解出 `4Kr0s5_Th0u54nDs_0f_yE4Rs_`，`9923-11-13 23:29:19Z` 解出 `u_f1nd_m3_1nTh3_sE4_oF_7imE`，拼接即 flag。

## 变体与关联

- 若程序用 `localtime` 而非 `gmtime`，需要按运行环境时区修正；比赛服务器时区通常是 UTC，但本机枚举时要显式使用 `timezone.utc`。
- 素数条件可能换成“日期是合数”“数字不含 4”“各位数字和为素数”等；方法相同：先找可枚举的小集合，再用快速素性测试筛选。
- 多素数 RSA 的变体：4 个以上素数、`e` 非常量、`phi` 计算错误等；先验证 `gcd(e, phi)=1`，再用 `pow(e,-1,phi)`。
- 与本库普通 RSA 卡片的区别：本场景的 `n`、`e` 不是文件中的常量，而是由时间约束动态构造，必须先枚举时间才能得到私钥。

## 检测与防御

- 检测特征：Qt/GMP 程序中出现 `__gmpz_probab_prime_p` 与时间格式化 `%04d%02d%02d%02d%02d%02d`；约束中出现多个 `is_prime` 调用；密文为超长十进制整数。
- 防御（真实系统）：不要把系统时间当作密钥材料或 RSA 参数；时间门应使用服务端签发的随机挑战，密钥应使用 CSPRNG 生成并安全存储。
- CTF 中先做约束剪枝再写爆破：月份、日、时的取值范围一旦确定，搜索量通常只有数万级，直接调用目标 DLL 比自写 Miller-Rabin 更快且与程序行为一致。
