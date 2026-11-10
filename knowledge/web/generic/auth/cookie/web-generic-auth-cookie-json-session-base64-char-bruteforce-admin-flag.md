---
id: web-generic-auth-cookie-json-session-base64-char-bruteforce-admin-flag
title: AES-CBC 加密 JSON 会话：按 base64 字符位爆破翻转 admin 字段（JSON 类型错误作 oracle）
type: scenario
domain: web
path: web/generic/auth/cookie
technique: aes-cbc-json-session-base64-char-bruteforce-type-error-oracle
aliases:
- Flask 会话伪造 admin
- base64 码表爆破改密文
- flipPin
- JSON 解析异常当预言机
- 加密 Cookie 位翻转爆破
- 文件名黑名单读 /proc
tags:
- flask
- aes-cbc
- cookie
- session-forgery
- bit-flip
- bruteforce
- oracle
- json
- path-trick
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:50:39+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。问题：黑名单为子串匹配 {self,cgroup,mountinfo,env,flag}，PoC 里 filename=/proc/1/cgroup 仍含 cgroup 会被 403，/proc/cpuset 也非有效路径，应改用 /proc/1/mounts 等等价路径；base64 单字符爆破 + JSON 解析错误 oracle 的主线表述与正文一致，下标需按实际会话长度校准。
---

## 一句话结论

服务端把 `{"admin": 0, "username": "user1"}` 这类 JSON 用 AES-CBC 加密后放进 Cookie（`base64(IV||密文)`），只要在密文中改动一个字节，就能让解密后的 JSON 里某一位发生可预测翻转；由于改哪一位、翻成什么值都不需要密钥，可以按 base64 字母表逐个字符爆破（64 次一轮），用「JSON 反序列化/类型错误导致 500 或固定报错」作为成功 oracle，把 `"admin": 0` 翻成 `"admin": 1` 拿到管理员分支，再借 `/proc` 下未被拉黑的别名文件读出敏感文件。

## 原理

- **CBC 翻转的性质**：解密满足 `P[i] = D(C[i]) XOR C[i-1]`。修改第 `i-1` 块密文的第 j 个字节，会使 `P[i]` 的第 j 个字节发生同样的异或差，而 `P[i-1]` 整块变成不可预测乱码。因此「改一个字节 → 目标块某字节翻转 + 前一块乱码」。
- **base64 让爆破变得可行**：Cookie 是 base64 文本，一个 base64 字符承载 6 bit，改动一个字符即改动密文中一个字节的低 6 位（或与相邻字符共享的位），对明文的影响是同一字节的位翻转而非整体乱码。在不知道密钥、不知道 IV、也不知道确切明文的情况下，按 64 个候选字符逐个替换、观察响应差异，即可定位到「能把目标字节改对」的那个字符。
- **为什么需要 oracle**：翻转后如果 JSON 结构被破坏（引号、逗号、括号被打坏），`json.loads` 抛异常，代码走到 `plain_session is None` 或 500 分支；如果刚好把 `0` 改成 `1`/其他真值，解析成功且 `session_data['admin']` 为真，进入文件读取分支。两类响应的差异（`don't hack me` / 500 报错页 vs 进入读文件逻辑）就是判断依据。
- **为什么只试 64 次**：题目会话结构固定、字段顺序固定，`admin` 的 `0` 在固定偏移；只需在对应 base64 位置上枚举字符，命中率与位数成正比，多访问几次即可稳定命中。
- **管理员判断只看真值**：`if session_data['admin']:` 对 `1`、`2`、`true`、非空字符串都为真，不必精确还原成 `1`，这降低了爆破难度。
- **黑名单是子串匹配**：读文件处 `any(b in filename for b in {'self','cgroup','mountinfo','env','flag'})`，只要绕过子串就能读同名信息：`/proc/self/cgroup` 被拉黑，但 `/proc/1/cgroup`、`/proc/cpuset`（`cpuset` 不含 `cgroup`）或 `/sys/fs/cgroup` 之外的等价路径仍可读；`mountinfo` 同理可用 `/proc/1/mountinfo` 之外的路径或 `/proc/self/mounts`（`self` 也被拉黑，需换 PID 或 `/proc/thread-self`）。

## 触发条件

- 会话 Cookie 为「AES-CBC 加密 + base64」，且没有 MAC/签名校验（解密失败只做异常捕获，不拒绝）。
- 解密后的明文被直接 `json.loads`，权限判断读取其中某个字段的真值（`admin`/`is_admin`/`role`）。
- 应用对不同失败原因给出**可区分**的响应（固定文案、状态码、报错页、耗时差异），可作为 oracle。
- 目标功能（如读文件、后台接口）在被判定为管理员后可达。

## 利用步骤

1. 访问一次受保护接口拿到初始 Cookie，base64 解码，确认结构为 `16 字节 IV + N 块密文`（长度减 16 能被 16 整除）。
2. 反复请求几次、拿到不同 IV 的 Cookie，对比可确认 IV 随机、密文块稳定，说明明文内容固定（同一默认会话）。
3. 定位 `admin` 字段所在块：从明文模板（如 `{"admin": 0, "username": "user1"}`）推算首块/次块边界，把目标 `0` 映射到 base64 串中的具体下标（一般落在十几位，取决于 IV 与块的偏移）。
4. 固定该下标，遍历 base64 字母表（`A-Za-z0-9+/`）替换字符，逐个请求受保护接口，记录响应；把「响应进入管理员分支」的字符记下。
5. 若一次爆破不足以翻转到真值（受共享位影响），联合调整相邻 1~2 个字符做二维搜索，或用多次响应差异收敛。
6. 得到能通过 `admin` 判断的 Cookie 后，请求文件读取接口；`filename` 用未被黑名单命中的等价路径（如换 PID、`/proc/cpuset`、`/proc/1/root/...`）读取目标文件。

## PoC

单字符 base64 爆破骨架（把响应差异当 oracle）：

```python
import base64, itertools, requests

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
COOKIE = 'base64(iv+ct) 形式的初始会话'
POS = 13  # admin 字段对应的 base64 下标，需按实际长度校准

def variants(c):
    raw = c  # 传入的 base64 文本
    for ch in ALPHABET:
        yield raw[:POS] + ch + raw[POS + 1:]

for cand in variants(COOKIE):
    r = requests.get('http://target/read', cookies={'session': cand},
                     params={'filename': '/proc/1/cgroup'}, allow_redirects=False)
    print(cand[POS], r.status_code, r.text[:80])
    # 记录返回进入业务逻辑（而非 don't hack me / 500）的候选字符
```

判定特征：

```text
失败: 返回固定文案（如 don't hack me）或 json 解析异常导致的 5xx
成功: 进入业务分支（返回文件内容 / 管理员页面），且响应长度与状态码明显不同
```

## 变体与关联

- 变体（已知明文位翻转）：若能确定整块明文，直接按 `IV' = IV XOR P_known XOR P_target` 构造（改 IV 只影响首块，零副作用），比爆破更快；本卡适用于「明文位置已知但字节值不确定、且无 oracle 可精确推断」的场景。
- 变体（oracle 形态）：除状态码/文案外，JSON 解析错误造成的响应时间差异、日志差异、后续接口行为差异都可当 oracle。
- 变体（黑名单绕过）：子串黑名单可被 `mounts`/`cpuset`/换 PID/`/proc/thread-self`/相对路径/`//` 等等价路径绕过；同理 `flag` 可用 `f*`、`/fla?`、软链或 `/proc/1/root/...` 规避（需目标文件系统权限允许）。
- 关联：[[web-generic-auth-cookie-cbc-bitflip-iv-first-block-role-forgery]]（同为 CBC 无签名会话伪造，但那张卡是已知明文 + 改 IV 精确构造首块，本卡是未知字节 + base64 单字符枚举 + JSON 错误 oracle）、[[web-generic-auth-myblog-hardcoded-aes-cookie-forgery]]（硬编码密钥可直接重签，无需翻转）。
- 边界：若会话带 HMAC/itsdangerous 签名，翻转后签名校验失败，该链失效；若应用对解密异常统一返回 200 空页，oracle 消失，需要改用长度/时间等间接信号；若 `admin` 字段跨块边界，翻转会同时破坏该块其他字节，需更多位组合。

## 检测与防御

- 代码修复：会话必须签名（itsdangerous/Flask 自带 secure cookie 或 JWT + HMAC），做到「加密 + 认证」；解密失败一律拒绝，不要只捕获异常继续。
- 权限判断：布尔型字段用 `is True` 严格比较，避免 `0`→`1` 之外的任意真值绕过；敏感字段放在签名保护的整体结构里，而非独立可翻转块。
- 响应一致性：对解密失败、JSON 解析失败、权限不足返回统一响应，避免形成 oracle。
- 文件读取：不要用「子串黑名单」防路径穿越，应做规范化 + 白名单根目录 + `realpath` 前缀校验；禁止读取 `/proc`。
- 检测：同一 Cookie 在短时间内被大量近似变体请求（仅个别字符不同）、大量 5xx 后紧跟成功的模式；URL 中出现 `/proc/`、`cpuset`、`mounts` 等探测路径。
