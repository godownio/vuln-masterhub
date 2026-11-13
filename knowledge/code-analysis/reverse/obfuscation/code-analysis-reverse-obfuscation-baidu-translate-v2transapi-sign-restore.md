---
id: code-analysis-reverse-obfuscation-baidu-translate-v2transapi-sign-restore
title: 百度翻译 v2transapi 的 sign 算法还原：断点定位 index.js 的 sign 赋值，抽 a/n 两个函数到 Node 并硬编码密钥 r
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: baidu-translate-v2transapi-sign-restore
aliases:
- 百度翻译 sign 逆向
- v2transapi 签名
- 百度翻译接口逆向
- 'sign: b(e)'
- '320305.131321201'
- n 函数位运算签名
- 翻译接口自动化
tags:
- javascript
- reverse
- frontend-signature
- api-automation
- devtools
- baidu
- translate
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:12:21+08:00'
  notes: '已对照原文与37张截图核对：img21-31复现链（sign: b(e)断点、r=320305.131321201、本地输出999424.762673与Network面板sign一致）与PoC一致；验证时用Node实跑卡片PoC，may→418756.164085、safe→999424.762673均与截图抓包sign一致（短ASCII输入）；修正frontmatter两个alias的YAML类型（sign: b(e)与320305.131321201加引号）。未验证点：PoC省略UTF-16代理对/超长截断分支，emoji/超30字符输入需按原文完整函数保留（边界已注明）。dedup候选为通用前端加密流程卡，related非重复。'
---

## 一句话结论

百度翻译网页版 `v2transapi` 的 `sign` 完全由前端 JS 生成：全局搜索 `sign:` 定位到压缩文件中的 `sign: b(e)`，断点步入得到 `a(t)` 与位运算辅助函数 `n(t,e)`，把两者抽到 Node、补上硬编码常量 `r = "320305.131321201"` 即可离线算出 `sign`，配合 `token`、`query` 等参数直接构造翻译请求（实测 `ts` 不参与校验）。

## 原理

- **签名参数**：请求 `v2transapi` 时只有 `sign` 与 `ts` 随 `query` 变化，`transtype` 在 `realtime`/`enter` 间切换；`sign` 是服务端校验请求合法性的关键字段。
- **定位方法**：`sign` 是常见参数名，Sources 里全局搜索 `sign:` 或 `sign=`，匹配到的文件逐个下断点；只有断在 `index.<hash>.js` 的 `sign: b(e)` 处会命中，说明该文件是签名入口。断住后可见实参 `t` 即用户输入的 `query`。
- **函数结构**：`a(t)` 负责：
  1. 处理 UTF-16 代理对与超长 query（长度 > 30 时取前 10 + 中间 10 + 后 10 字符）；
  2. 把字符按 UTF-8 规则编码成字节数组 `g`；
  3. 以硬编码常量 `r = "320305.131321201"` 的整数部分 `f` 为初值、小数部分 `m` 为盐，用 `n(t, e)` 做多轮位运算混合；
  4. 结果与 `m` 异或、对 1e6 取模，输出字符串 `b + "." + (b ^ f)`。
- **`n(t, e)` 位运算**：`e` 是三字符一组的选择器（如 `"+-a^+6"`、`"+-3^+b+-f"`），逐组读取 `e.charAt(n+2)`（字母转 `charCode-87`，数字直接转），按 `e.charAt(n+1)` 为 `+` 时 `t >>> r` 否则 `t << r`，再按 `e.charAt(n)` 为 `+` 时 `(t + r) & 0xFFFFFFFF` 否则 `t ^ r`，循环推进。本质是 base64 字符表驱动的移位/加/异或混合，不是标准哈希。
- **为什么能离线复现**：算法、常量都在 JS 里，服务端只校验结果；Node 与浏览器位运算语义一致。抽函数运行时出现的 `r`/`n` 未定义错误，分别是硬编码常量与辅助函数，补齐即可。
- **`ts` 的作用**：原文实测 `ts` 值不影响翻译，可固定或取任意值；`token` 沿用抓包值即可。

## 触发条件

- 百度翻译网页版接口（`v2transapi`，原文 2024-02-24 版本）可从浏览器正常发起请求，DevTools 可断点调试。
- 服务端签名校验不绑定会话一次性 nonce、不校验设备指纹（本例只校验 sign/token 等参数）。
- 能访问登录态或匿名可用的接口（原文为未登录状态）。
- 目标 JS 未做防调试（或有办法绕过，见反调试卡）。

## 利用步骤

1. 抓一次正常翻译请求，记录 `v2transapi` 的 URL、`query`、`sign`、`ts`、`token`、`transtype`、`domain` 等字段。
2. DevTools Sources 全局搜索 `sign:`，在候选文件的赋值处下断点，触发翻译，确认命中 `index.<hash>.js` 的 `sign: b(e)`。
3. 步入函数，确认实参是 `query`；继续步入，找到 `window[d]` 被赋值为 `320305.131321201`（`d` 由 `gtk` 字符拼成，`r` 即该常量）。
4. 把 `a(t)`、`n(t,e)` 两个函数抽到本地 Node 脚本；运行报 `r is not defined` 时硬编码 `r="320305.131321201"`，报 `n is not defined` 时补入 `n` 函数。
5. 用同一 `query` 运行本地脚本，与抓包 `sign` 对比一致即还原成功。
6. 组装请求（`query`、`sign`、`ts`、`token` 等），实现批量翻译自动化；`ts` 可固定。

## PoC

```javascript
function n(t, e) {
    for (var n = 0; n < e.length - 2; n += 3) {
        var r = e.charAt(n + 2);
        r = "a" <= r ? r.charCodeAt(0) - 87 : Number(r);
        r = "+" === e.charAt(n + 1) ? t >>> r : t << r;
        t = "+" === e.charAt(n) ? t + r & 4294967295 : t ^ r;
    }
    return t;
}

function a(t) {
    // 省略 UTF-16 代理对/超长截断处理，按原文完整函数保留
    var r = "320305.131321201";
    var h = r.split("."), f = Number(h[0]) || 0, m = Number(h[1]) || 0;
    var g = [], y = 0;
    for (var v = 0; v < t.length; v++) {
        var _ = t.charCodeAt(v);
        _ < 128 ? g[y++] = _ : (_ < 2048 ? g[y++] = _ >> 6 | 192 : (
            55296 == (64512 & _) && v + 1 < t.length && 56320 == (64512 & t.charCodeAt(v + 1))
                ? (_ = 65536 + ((1023 & _) << 10) + (1023 & t.charCodeAt(++v)),
                   g[y++] = _ >> 18 | 240, g[y++] = _ >> 12 & 63 | 128)
                : g[y++] = _ >> 12 | 224,
            g[y++] = _ >> 6 & 63 | 128), g[y++] = 63 & _ | 128);
    }
    var b = f;
    var w = "+-a^+6", k = "+-3^+b+-f";
    for (var x = 0; x < g.length; x++) b = n(b += g[x], w);
    b = n(b, k);
    (b ^= m) < 0 && (b = 2147483648 + (2147483647 & b));
    return "".concat((b %= 1e6).toString(), ".").concat(b ^ f);
}

const query = "abandon";
console.log(`from=en&to=zh&query=${query}&simple_means_flag=3&sign=${a(query)}&token=<抓包token>&domain=common&ts=<任意值>`);
```

## 变体与关联

- 变体一：同样的“断点定位签名赋值 → 抽函数 → 补 ReferenceError 依赖”流程适用于绝大多数前端签名接口，见 [[code-analysis-reverse-frontend-request-response-encryption-automation]]。
- 变体二：若签名函数被混淆为 `_0x` 字符串数组，先做反混淆再抽函数（见 AI 解混淆/字符串数组还原卡）。
- 关联：[[code-analysis-reverse-obfuscation-youdao-translate-sign-aes-decrypt]]（同文章另一翻译接口案例，签名 + 响应 AES 解密）。
- 边界：`a()` 中的超长 query 截断与 UTF-16 代理对处理必须原样保留，否则含 emoji/生僻字或超 30 字符时结果不一致；接口若增加一次性 nonce/设备指纹/验证码，需同步获取或放弃；原文脚本未在本机执行，但抓包 sign 与本地计算结果一致为原文实测。

## 检测与防御

- 检测：同一 IP/会话出现高频、参数规律递增的 `v2transapi` 请求；sign 全部合法但无浏览器指纹/TLS 指纹异常；`ts` 固定重复。
- 防御：给签名加入服务端 nonce（一次性）与时间窗口、会话/设备绑定；对翻译接口做频控与风控；不要依赖前端签名防自动化（前端可见即等于可复现）。
- 加固：敏感接口要求登录态与配额；对异常客户端特征（无 Referer、UA 不一致）做拦截。
