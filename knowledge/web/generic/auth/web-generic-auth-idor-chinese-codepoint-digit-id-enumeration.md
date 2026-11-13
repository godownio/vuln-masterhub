---
id: web-generic-auth-idor-chinese-codepoint-digit-id-enumeration
title: 用户信息接口数字 ID 被汉字逐位替代（U+4E10–U+4E19 对应 0–9）：URL 解码还原后遍历越权批量读取用户信息
type: scenario
domain: web
path: web/generic/auth
technique: idor-numeric-id-cjk-codepoint-digit-substitution
aliases:
- 汉字数字 ID
- 汉字编码 id 越权
- 丐丑丒专且丕世丗丘丙
- 自定义数字映射绕过
- ID 混淆越权遍历
- CJK digit substitution IDOR
tags:
- web
- auth
- idor
- access-control
- parameter-tampering
- encoding-obfuscation
- user-enumeration
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T16:46:19+08:00'
  notes: 已对照原文全文与图06核对：id=%E4%B8%94%E4%B8%98%E4%B8%96%E4%B8%93解码为且丘世专=4863，映射表丐丑丒专且丕世丗丘丙=U+4E10-U+4E19对应0-9，经本地Python复算enc/dec与URL编码一致；响应JSON含id/userName/userLevel/password/phoneNum等字段(图06)成立；与库内user-api明文口令枚举卡为不同技巧(编码混淆还原vs直接接口遍历)，非同链；原文未给受影响版本。
---

## 一句话结论

某站用户信息接口的 `id` 参数取值是一串 URL 编码的汉字（如 `%E4%B8%94%E4%B8%98%E4%B8%96%E4%B8%93`，解码为“且丘世专”），实际是把数字 0–9 逐位替换成码点连续的十个汉字（丐丑丒专且丕世丗丘丙，U+4E10–U+4E19 依次对应 0–9），按位还原得到真实数字 ID（此处为 4863）后顺序遍历，即可越权读取大量用户资料，响应中还会带出密码、手机号等敏感字段。

## 原理

- 越权的成立与编码无关：服务端按传入的 `id` 查出对应用户并原样返回，却没有校验该对象是否属于当前登录用户，属于典型的 IDOR（不安全的直接对象引用）。
- 数字替换只是表示层混淆：这十个汉字的 Unicode 码点恰好连续（丐 U+4E10、丑 U+4E11、丒 U+4E12、专 U+4E13、且 U+4E14、丕 U+4E15、世 U+4E16、丗 U+4E17、丘 U+4E18、丙 U+4E19），按 `码点 - 0x4E10` 即得数字，因此“且丘世专”= 4,8,6,3 = 4863。作者用 FUZZ 对每个位置的字符与返回结果对照，验证了逐位映射。
- 这种替换可能用于规避常规工具对自增数字 ID 的扫描、绕过对纯数字参数的 WAF 规则，或作为前端自定义字体/数字混淆的残留；但只要解码规则可逆，顺序遍历仍然成立。
- 响应返回完整用户对象（id、userName、userLevel、password、phoneNum、isValid、code、unit、proTitle、email 等），属于敏感字段过度返回，进一步放大了越权收益（截图中部分敏感值被作者打码）。

## 触发条件

- 业务接口用客户端可控的对象标识（这里是 `id`）查询并返回用户资料；
- 服务端只按对象存在性查询，不校验会话用户与该对象的归属（或不校验登录态）；
- ID 空间可枚举（自增数字或可预测），即使被汉字/编码包装，只要映射可还原即可遍历。

## 利用步骤

1. 登录普通账号，浏览个人中心类接口，抓到一个携带 `id` 参数的请求，例如 `GET /XXX?id=%E4%B8%94%E4%B8%98%E4%B8%96%E4%B8%93`；
2. URL 解码得到“且丘世专”，初看不像 ID，但注意到字符都落在 U+4E10–U+4E19 连续区间；
3. 对每个位置的字符做 FUZZ/对照，建立映射：丐丑丒专且丕世丗丘丙 = 0–9；
4. 将目标 ID 按位替换回汉字并 URL 编码（如 4863 → 且丘世专 → `%E4%B8%94%E4%B8%98%E4%B8%96%E4%B8%93`），或直接用工具按映射批量生成；
5. 顺序遍历 ID，收集响应中的用户资料；原文截图显示大量 `200` 响应与含 password/phoneNum 等字段的 JSON。

## PoC

```python
# 仅演示映射与编码，不针对任何真实目标
mapping = "丐丑丒专且丕世丗丘丙"   # U+4E10..U+4E19 -> 0..9
def enc(n: int) -> str:
    return "".join(mapping[int(d)] for d in str(n))
def dec(s: str) -> int:
    return int("".join(str(ord(c) - 0x4E10) for c in s))
assert enc(4863) == "且丘世专" and dec("且丘世专") == 4863
```
请求侧把 `quote(enc(target_id))` 填入 `id` 参数即可。

## 变体与关联

- 同类伪装：其他连续码点区间的字符替换（全角数字、罗马数字、圈码数字、地区数字字符）、Base64/十六进制包装的自增 ID、前端自定义字体把数字渲染成汉字而参数其实仍是数字；
- 解码思路通用：先 URL 解码/Base64 解码，再检查字符码点是否连续或与数字构成固定偏移；
- 与库内“IDOR 接口面扩展”“不可遍历 ID 的两段式越权”可组合：先识别编码，再枚举或串联查询接口。

## 检测与防御

- 服务端对每个对象读取做归属/角色校验，禁止仅凭 ID 返回他人资料；敏感字段（password、phoneNum 等）按最小必要原则裁剪；
- 使用不可预测的对象标识（UUID/雪花 ID + 服务端映射），不要把自增 ID 只做表面编码；
- 监控同一账号在短时间内对大量不同 ID 的访问、以及 URL 中非 ASCII 参数的高频模式；
- 不要依赖“参数看起来不像数字”作为防遍历手段，编码可逆即等于明文。
