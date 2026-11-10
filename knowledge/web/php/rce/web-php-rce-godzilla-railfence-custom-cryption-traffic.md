---
id: web-php-rce-godzilla-railfence-custom-cryption-traffic
title: 哥斯拉自定义 Cryption 栅栏加密混淆流量：Base64→3 栏栅栏→Base64 与配套 PHP 马
type: scenario
domain: web
path: web/php/rce
technique: godzilla-railfence-custom-cryption-traffic
aliases:
- Godzilla 栅栏加密
- 哥斯拉流量混淆
- ming9 加密器
- 哥斯拉自定义 Cryption
- rail fence webshell traffic
- PHP_XOR_BASE64 魔改
tags:
- php
- webshell
- godzilla
- traffic-obfuscation
- rail-fence
- base64
- custom-cryption
- evasion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T03:08:31+08:00'
  notes: 已通读全文(含三段超长样例的头部/长度并以脚本复原)与12张图片核对：PhpXor 的 E/D(functions.md5 前后16位边界、XOR key[(i+1)&15]、base64)与配套 PHP 马一致；ming9 去掉 XOR、E 改为 Base64→3栏栅栏→Base64、PHP 马 base64_decode(decode(base64_decode())) 与原文代码一致；对文中样例实测：472 行 69624 字符 Base64 解码=478 行 52216 字符栅栏串，按 quotient/remainder n=3 还原=484 行 52216 字符内层 Base64，再解码为 '=array(); function run(){...}' 39162 字节 PHP payload，与卡片描述完全吻合；测试连接 Success by ming! 与 Burp 首包截图一致。无 sources/文章ID/长段摘录(仅必要代码/示意)；路径合法。非组件 CVE，无 affected_versions 且正确。未验证点：未在真实环境重建 jar 复测，依据原文截图与样例数据复原。
---

## 一句话结论

哥斯拉（Godzilla）的请求/响应加密由 `Cryption` 模块决定；以 `PHP_XOR_BASE64` 为模板删掉 XOR，把客户端 `E` 改为「Base64 → 3 栏栅栏（rail fence）→ Base64」、服务端配套 PHP 马按「Base64 解码 → 栅栏还原 → Base64 解码 → run」处理，就能让流量不再符合标准哥斯拉的 XOR+Base64 特征，同时客户端仍能正常连接与执行命令。

## 原理

- **加密器插拔机制**：哥斯拉 `ShellSetting.testButtonClick → updateTempShellEntity → ShellContext.initShellOpertion()` 中调用 `ApplicationContext.getCryption(payload, cryption)`，按 `CryptionAnnotation(Name=..., payloadName=...)` 反射实例化加密器；`init()` 负责把 payload 发到服务端并存 session，后续请求/响应走 `encode`/`decode`（`isSendRLData()==true` 表示请求体要再做 URL 编码）。因此只要复制一份 `phpXor` 加密器改 `E`/`D` 并重新打 jar，就能换掉整条流量的封装。
- **原生 PHP_XOR_BASE64**：`E` 对字节逐位 `cs[i] ^= key[(i+1)&15]` 后 Base64，拼成 `pass=<urlencoded base64>`；`D` 先 Base64 解码再同样 XOR。响应用 `md5(pass+key)` 前 16/后 16 个十六进制字符做边界（`findStr`），这是哥斯拉流量的标准指纹。
- **自定义 ming9 加密器**：把 XOR 去掉（`E` 只做 Base64，`D` 只做 Base64 解码），再在两端各加一层栅栏置换：
  - 客户端 `E`：先 `Base64.getEncoder().encodeToString(cs)` 得到字符串；取 `n=rails`（案例 3），把字符按 `rail=(rail+1)%n` 轮流追加到 `railFence[0..n-1]`，再把各 rail 依次拼接；最后对拼接结果整体再 Base64 一次，作为 `pass` 参数发送。
  - 服务端 PHP：`$data=base64_decode(decode(base64_decode($_POST[$pass])))`。`decode($str)` 按 `n=3` 计算 `quotient=floor(len/n)`、`remainder=len%n`，前 `remainder` 个 rail 各多 1 个字符，把输入按行切回 n 段后按列读取，即还原栅栏前的 Base64 字符串；再 Base64 解码得到模块数据。
  - 响应方向只做 Base64（`echo base64_encode(@run($data))`），客户端 `D` 单次 Base64 解码。
- **为什么能混淆**：栅栏是换位密码，不改变字符集合，但会打乱 Base64 串的字符顺序；外层再 Base64 后，请求体是普通 Base64 文本，不含标准哥斯拉响应的 `md5(pass+key)` 前后缀，也没有 XOR 后 Base64 的结构特征，常规基于哥斯拉流量特征（参数名+固定响应框架+Base64 解码后可见 payload）的检测会被绕过。服务端按 quotient/remainder 切分即可无损还原，两端算法必须严格一致。
- **代价与边界**：自定义加密器只改变流量外观，服务端仍然 `eval` 会话中的 payload、仍然执行 `run()`；文件落地形态、session 行为、请求体积（首包大、后续包小）等行为特征仍在。换加密器后标准哥斯拉客户端无法连接，必须使用同一份魔改客户端生成与连接。

## 触发条件

- 攻击者能修改哥斯拉源码并重新构建 jar（或编写等价客户端），且能生成并上传配套 PHP 马到目标站点。
- 目标 PHP 版本支持所用语法（案例 PHP 7.3/7.4 环境），Web 进程对 session 可写。
- 服务端马与客户端加密器版本一致（`rails`、Base64 层数、参数名一致），否则解密失败。
- 仅改变流量特征，不改变利用能力；是否绕过特定 WAF/IDS 取决于对方规则是否只匹配标准哥斯拉指纹。

## 利用步骤

1. 定位并复制加密器：在哥斯拉源码 `shells/cryptions/phpXor/` 旁新建包（如 `ming9`），复制 `PhpXor` 类与 `base64.bin` 模板，修改 `@CryptionAnnotation(Name="ming9", payloadName="PhpDynamicPayload")`。
2. 修改客户端 `E`：去掉 XOR 循环，实现「Base64 → 按 rails 轮流分配到 n 个 StringBuilder → 拼接 → 再 Base64」，返回值仍拼成 `pass=<urlencoded 结果>`；`D` 改为单次 Base64 解码。
3. 修改 payload 模板 `base64.bin`：删除 `encode($D,$K)` 的 XOR 逻辑（保留空实现或去掉调用），把入口改为 `base64_decode(decode(base64_decode($_POST[$pass])))`，并加入按 quotient/remainder 切分的栅栏还原函数；响应改为 `base64_encode(@run($data))`。
4. 重新构建 jar，用魔改客户端「生成」木马并上传；在 Shell 设置中选择 `ming9` 加密器，代理到 Burp，点击「测试连接」确认 `Success`。
5. 分析/验证流量：对 `pass` 值先 Base64 解码得到栅栏串，按 n=rails 还原后再 Base64 解码，应能看到 PHP payload/模块指令；响应 Base64 解码即执行结果。

## PoC

客户端 `E`（rails=3，栅栏分配 + 双层 Base64）：

```java
public byte[] E(byte[] cs) {
    String b64 = Base64.getEncoder().encodeToString(cs);
    int n = 3;
    StringBuilder[] railFence = new StringBuilder[n];
    for (int i = 0; i < n; i++) railFence[i] = new StringBuilder();
    int rail = 0;
    for (int i = 0; i < b64.length(); i++) {
        railFence[rail].append(b64.charAt(i));
        rail = (rail + 1) % n;
    }
    StringBuilder fence = new StringBuilder();
    for (int i = 0; i < n; i++) fence.append(railFence[i]);
    return ("pass=" + Base64.getEncoder().encodeToString(
            fence.toString().getBytes())).getBytes();
}
```

服务端 PHP 栅栏还原与入口：

```php
function decode($str){
    $n = 3; $len = strlen($str);
    $q = (int)($len / $n); $r = $len % $n;
    $table = array(); for ($i = 0; $i < $n; $i++) $table[$i] = array();
    $idx = 0;
    for ($i = 0; $i < $n; $i++) {
        $rows = $q + ($i < $r ? 1 : 0);
        for ($j = 0; $j < $rows; $j++) $table[$i][$j] = $str[$idx++];
    }
    $out = "";
    for ($i = 0; $i < $q + 1; $i++)
        for ($j = 0; $j < $n; $j++)
            if (isset($table[$j][$i])) $out .= $table[$j][$i];
    return $out;
}
$data = base64_decode(decode(base64_decode($_POST['pass'])));
// ... eval 会话 payload 后：
// echo base64_encode(@run($data));
```

（案例中第一次请求的 `pass` 外层 Base64 解码后是一段三栏栅栏串，再还原并 Base64 解码即含 `$parameters=array(); function run($pms){...}` 的 payload。）

## 变体与关联

- 变体：`rails` 可改成任意 n；也可把栅栏换成列置换、反转、异或移位等可逆变换，或叠加 AES/RSA 等强加密（见关联卡）。
- 变体：响应方向同样可加栅栏/二次 Base64，只需客户端 `D` 对应调整；案例为简化只对请求加栅栏。
- 关联：[[web-php-rce-godzilla-aes-session-webshell-disguise]]（哥斯拉 PHP 马另一魔改方向：AES-128-ECB + username/password 登录伪装）。
- 关联：[[defense-forensics-godzilla-php-webshell-traffic-decode]]（标准哥斯拉 PHP 流量识别与解密，可用于对照基线特征）。
- 关联：[[web-php-rce-webshell-rsa-traffic-encoder]]（蚁剑自定义编码器 RSA 加密流量，同类「客户端/服务端成对改加密器」思路）。
- 边界：只改流量编码，不具备免杀客户端/服务端文件的额外能力；自定义客户端是连接前提，标准客户端无法解密该流量。

## 检测与防御

- 流量侧：自定义加密后标准哥斯拉指纹失效，检测不能只靠固定参数名/响应框架；应对「PHPSESSID + 首包大 / 后续包小」的两阶段模式、以及 Base64 大块请求体做多层解码尝试（Base64 → 栅栏候选 n=2..8 → Base64），看是否还原出 PHP 代码或模块指令。
- 主机侧：监控 Web 目录新增/变更的 PHP 文件、PHP 进程异常子进程、`eval`/`assert` 类行为；哥斯拉马虽然流量加密，文件中的 session/eval 结构与上传行为仍在。
- 代码/文件层：扫描含 `session_start` + `eval($_SESSION[...])` + Base64/XOR 组合的 PHP 文件；对疑似马提取参数名与加密逻辑，反推自定义层。
- 防御加固：禁用 Web 目录写权限、限制上传类型、部署 PHP 禁用危险函数/`disable_functions`，并对管理员账号与 WebShell 落地做完整性监控；WAF 规则需覆盖非标准编码链而不仅是已知哥斯拉特征。
