---
id: crypto-prng-srand-time-seed-2fa-code-prediction
title: srand(time(NULL)) 时间种子 2FA 验证码预测绕过
type: scenario
domain: crypto
path: crypto/prng
technique: time-seeded-srand-2fa-prediction
tags:
- prng
- srand
- glibc
- 2fa
- authentication
- time-seed
- ctypes
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V83
  verified_at: '2026-11-05T17:50:17+08:00'
  notes: 已对照原文与图04/05/06核对：Gitea main.c 确为 srand(time(NULL))、num[0]='1'+rand()%9、LEN=64，图06 预测2FA后进入功能菜单，图05 用该口令 dump 成功。卡内西班牙语月份解析、ctypes 调用本地 glibc、±秒种子补偿与原文 time-2 做法一致；PoC 未复跑；无组件版本。
url: /docs/crypto/prng/crypto-prng-srand-time-seed-2fa-code-prediction/
draft: false
kb_aliases:
- srand 时间种子预测
- 2FA 验证码预测
- libc rand 复现
- 时间种子验证码
- 可预测二次验证码
---

## 一句话结论

当二次验证码由 C 程序 `srand(time(NULL)); rand()` 逐位生成时，整个验证码只是登录时刻的函数；从服务端登录横幅读取其时间与时区，在本地用同一 libc 复现同样的 `rand()` 序列，即可算出 2FA 并完成登录。

## 原理

- `srand(seed)` 为 glibc 的 `rand()` 设置确定性伪随机序列；同一实现、同一种子必然产生同一串输出。`time(NULL)` 的精度只到秒，因此种子空间极小。
- 生成逻辑是固定的：第一位 `1 + rand() % 9`（1–9，避免前导零），其后 63 位各取 `rand() % 10`，拼成 64 位数字验证码。只要种子对上，64 位全部可复现。
- 登录服务在认证前打印 `date` 风格的横幅（如 `sáb 28 feb 2026 10:19:25 -03`），同时泄露了目标当前时间与时区偏移，这台服务器的时间与本地时钟的偏差不需要猜。
- 把横幅解析成带时区的 `datetime`，用 `timestamp()` 得到 Unix 秒作为种子，再通过 `ctypes.CDLL("libc.so.6")` 调用本地 glibc 的 `srand/rand`，即可得到与目标一致的序列。网络延迟或取整误差会导致种子差 1–2 秒，实际利用时枚举相邻几秒即可。
- 与之相对，标准 TOTP/HOTP 使用服务端与客户端共享的密钥做 HMAC，验证码不可由公开时间推导；本场景成立的前提是“自研验证码生成器把 PRNG 当成了安全随机数”。

## 触发条件

- 验证码由 `rand()`/`srand()` 等非密码学 PRNG 生成，且种子来自可预测值（时间、PID、递增数）。
- 生成算法或源码泄露（公开仓库、二进制、反编译），能确定字符集、长度与取模方式。
- 服务端在认证前回显时间，或攻击者能通过其他渠道得知目标时钟与时区。
- 攻击机与目标使用兼容的 libc 实现（本文为 Linux glibc）；跨平台需在匹配的容器中运行复现脚本。
- 验证码没有与用户/会话绑定的一次性随机盐，或绑定关系可由攻击者复现。

## 利用步骤

1. 获取验证码生成逻辑：审计公开代码仓库、反编译目标二进制，确认 `srand(time(NULL))` 与逐位 `rand()` 的取模规则。
2. 连接登录服务，读取第一行时间横幅，解析出年月日时分秒与时区（注意西班牙语等本地化月份缩写）。
3. 把该时间转换为 Unix 时间戳作为种子；用 `libc.srand(seed)` 初始化本地 glibc。
4. 按生成逻辑计算 64 位验证码：第一位 `1 + rand() % 9`，其余 63 位 `rand() % 10`。
5. 提交用户名、口令和验证码；若失败，对种子 ±1、±2 秒重试（网络延迟/服务器取整）。
6. 登录成功后继续使用该会话，验证码只在本次登录有效时无需持久化。

## PoC

目标侧生成逻辑（C）：

```c
#include <stdlib.h>
#include <time.h>

#define LEN 64

void gen(void) {
    char num[LEN + 1];
    srand(time(NULL));
    num[0] = '1' + rand() % 9;
    for (int i = 1; i < LEN; i++)
        num[i] = '0' + rand() % 10;
    num[LEN] = '\0';
    printf("Generated code: %s\n", num);
}
```

攻击侧复现（Python + ctypes，需在与目标一致的 glibc 环境运行）：

```python
import ctypes, re
from datetime import datetime, timezone, timedelta

libc = ctypes.CDLL("libc.so.6")
libc.srand.argtypes = (ctypes.c_uint,)
libc.rand.restype = ctypes.c_int

banner = "sáb 28 feb 2026 10:19:25 -03"   # 登录前服务端回显
months = {"ene":1,"feb":2,"mar":3,"abr":4,"may":5,"jun":6,
          "jul":7,"ago":8,"sep":9,"oct":10,"nov":11,"dic":12}
m = re.search(r"(\d+) (\w+) (\d+) (\d+):(\d+):(\d+) ([+-]\d+)", banner)
day, mon, year, hh, mm, ss, tz = m.groups()
dt = datetime(int(year), months[mon.lower()], int(day),
              int(hh), int(mm), int(ss),
              tzinfo=timezone(timedelta(hours=int(tz))))

for skew in (0, -1, -2, 1, 2):          # 补偿网络延迟与秒级取整
    libc.srand(int(dt.timestamp()) + skew)
    code = str(1 + libc.rand() % 9)
    code += "".join(str(libc.rand() % 10) for _ in range(63))
    print(skew, code)
```

## 变体与关联

- 变体：PHP `srand(time())`/`mt_srand(time())`、Java `new Random(System.currentTimeMillis())`、Python `random.seed(time.time())` 等时间播种 PRNG，思路相同：同步时钟后本地复现。
- 变体：若只能拿到若干连续输出（例如多个验证码），可反推 MT19937 状态或线性同余参数，预测后续输出。
- 变体：种子若由 PID 或递增计数器构成，空间同样很小，可枚举。
- 关联：[[crypto-prng-math-random-sharekey-recovery]]（同属 PRNG 输出决定安全敏感值，但恢复方式依赖客户端 hook）；[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（2FA 参数篡改与验证码爆破）。
- 边界：若生成器改用 `getrandom`/`/dev/urandom`/`RAND_bytes`，或验证码由 TOTP 密钥计算，则本方法失效；若服务端不在认证前泄露时间且本地时钟偏差大，只能盲枚举秒级种子，成功率随窗口增大而下降。

## 检测与防御

- 检测：代码审计中搜索 `srand(time`、`mt_srand(time`、`Random(System.currentTimeMillis)` 等时间播种模式；监控同一账号短时间内连续提交多个相邻时间对应的验证码；观察验证码只随时间变化、与用户无关的规律。
- 修复：验证码改用 CSPRNG（`getrandom`、`/dev/urandom`、`RAND_bytes`）；生产环境应使用标准 TOTP/HOTP，并以每用户密钥作为 HMAC 输入。
- 加固：认证前不打印服务器时间；验证码绑定用户与会话并一次性使用；限制尝试次数并加入失败延迟，即使算法可预测也提高枚举成本。
