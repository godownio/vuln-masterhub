---
id: web-generic-auth-captcha-parameter-controlled-universal-code
title: 验证码可绕过：字符集/尺寸由请求参数控制、万能码 8888/0000、不销毁重用与图片地址暴露
type: scenario
domain: web
path: web/generic/auth
technique: captcha-parameter-controlled-universal-code-reuse
tags:
- captcha
- auth-bypass
- business-logic
- thinkcmf
- vote
- bruteforce
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V664
  verified_at: '2026-11-13T08:17:59+08:00'
  notes: 已对照原文与验证码相关截图核对：ThinkCMF Checkcode URL（127.0.0.1/index.php?g=Api&m=Checkcode&a=index&code_len=4&font_size=15&width=100&height=...&charset=2222）、万能码空值/8888/0000/1111…9999、尺寸可控、简单验证码OCR识别、会话绕过、接码平台均与原文一致；删除原文未列举的1234。原文对ThinkCMF仅标注1.X-2.X且细节少，confidence medium如实；尺寸可控的DDoS（PHPcms）按规则未展开、卡内注明聚焦绕过。affected_versions 原文无标记保持null。未验证点：未复现Checkcode接口。
url: /docs/web/generic/auth/web-generic-auth-captcha-parameter-controlled-universal-code/
draft: false
kb_aliases:
- 验证码字符集可控
- ThinkCMF 验证码可控
- 验证码万能码
- 验证码不销毁
- 验证码尺寸可控
- captcha 绕过
---

## 一句话结论

投票/登录前的图形验证码若实现不当——字符集、长度、尺寸等由 URL 请求参数控制（如 ThinkCMF 1.X-2.X 的 `Checkcode` 接口 `code_len/font_size/width/height/charset`），验证码使用后不销毁可重复提交，图片地址暴露可直接获取答案，或存在空值/`8888`/`0000` 等开发遗留万能码——则验证码形同虚设，可被自动化识别或直接绕过，用于刷票与登录爆破。

## 原理

- **验证码参数可控 = 答案可控**：验证码生成接口若从请求参数读取字符集 `charset`、长度 `code_len`、字体/尺寸，攻击者可把字符集固定成已知字符（原文 ThinkCMF 案例：`index.php?g=Api&m=Checkcode&a=index&code_len=4&font_size=15&width=100&height=...&charset=2222`，验证码被生成成固定样式/字符集，答案可预测或极易识别）。参数由客户端控制意味着"随机性"可被攻击者削减。
- **验证码不销毁**：校验通过后服务端没有作废该验证码（或没有重新生成），同一个验证码可反复用于多次提交，验证码退化为一次性已知常量，批量投票/爆破只需识别一次。
- **图片地址暴露**：验证码图片 URL 可预测/可被直接访问读取（无一次性绑定），攻击者可先取图识别再提交。
- **万能码**：开发调试遗留的空值、`8888`、`0000`、`1111`…`9999` 等捷径校验未被删除，任意输入这些值即通过。
- **尺寸可控 → 识别成本降低**：把 `width/height` 改小使验证码只含极少像素/单字符，OCR 或人工批量识别几乎零成本（原文也提到 PHPcms 早期版本验证码尺寸可控被用于消耗资源，但本卡聚焦绕过而非拒绝服务）。
- **会话绕过**：验证码通常绑定会话；尝试次数多后出现验证码，清空缓存/换隐私窗口获得新会话即可回到"无需验证码"阶段。

## 触发条件

- 验证码生成/校验由客户端参数影响（字符集、长度、尺寸等）。
- 验证码校验后不失效/不刷新，或校验逻辑存在空值/万能码短路。
- 验证码图片可预测访问；或验证码过于简单可被 OCR。
- 存在可被反复尝试的投票/登录/注册接口。

## 利用步骤

1. 抓包观察验证码请求与校验请求，记录验证码生成 URL 及其参数（`code_len`、`charset`、`width`、`height` 等）。
2. 尝试控制生成参数：固定 `charset`/`code_len` 或缩小尺寸，观察验证码是否变得可预测/易识别（原文 ThinkCMF 示例）。
3. 测试重用：用同一验证码连续提交多次，观察是否一直成功（不销毁）。
4. 测试万能码：提交空值、`8888`、`0000`、`1111`…`9999` 等，观察是否直接通过。
5. 检查验证码图片 URL 是否可预测/无需会话即可访问，必要时配合 OCR（已有 OCR 卡）自动识别。
6. 若出现验证码的触发基于会话尝试次数，清空 Cookie/开隐私窗口换新会话回到无验证码阶段。
7. 用上述任一口子批量投票/登录爆破。

## PoC

```text
# ThinkCMF 1.X-2.X 验证码字符集/尺寸可控（原文示例 URL 形态）
GET /index.php?g=Api&m=Checkcode&a=index&code_len=4&font_size=15&width=100&height=50&charset=2222
# 页面验证码变成可控字符集，答案可预测/易识别
```

```text
# 万能码测试（原文列举）
空值 / 8888 / 0000 / 1111 ... 9999
```

## 变体与关联

- 变体：验证码图片地址暴露、验证码可重复使用、OCR 识别（参见 [[web-generic-auth-captcha-ocr-username-enum-bruteforce]]、[[web-generic-auth-captcha-ocr-username-enumeration-same-password]]）。
- 变体：客户端生成/客户端校验验证码（[[web-generic-auth-client-generated-captcha-md5-key-signature-forge]]、[[web-generic-auth-captcha-client-refresh-session-reuse]]）。
- 关联：[[web-generic-vote-anti-replay-client-ua-cookie-ip-bypass]]（验证码被绕过后投票防重进一步失效）、[[web-generic-auth-captcha-double-md5-jsrpc-yakit-login-bruteforce]]（验证码 + 登录爆破组合）。
- 边界：验证码由服务端强随机生成、一次性、绑定会话且答案不可从参数推断时，上述绕过失效（仍需 OCR 对抗）。

## 检测与防御

- 检测：短时间内同一验证码/同一图片 ID 被多次提交；验证码生成请求中包含 `charset/width/height/code_len` 等参数且被异常修改；登录/投票接口高频失败后成功；空验证码或固定值（8888 等）提交记录。
- 修复：验证码生成参数全部服务端固定/随机，不读取客户端可控参数；校验成功后立即作废并刷新；验证码会话绑定且图片一次性；删除万能码/空值短路逻辑；对暴力尝试做频次限制。
- 加固：使用成熟验证码组件并定期评估 OCR 抗性；关键操作叠加服务端风险评分与设备指纹；监控验证码接口异常调用。
