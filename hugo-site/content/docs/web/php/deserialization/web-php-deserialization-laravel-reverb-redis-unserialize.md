---
id: web-php-deserialization-laravel-reverb-redis-unserialize
title: Laravel Reverb 经 Redis Pub/Sub 消息触发的无限制 unserialize 对象注入（CVE-2026-23524）
type: scenario
domain: web
path: web/php/deserialization
technique: redis-pubsub-unserialize-object-injection
tags:
- php
- laravel
- reverb
- redis
- pubsub
- deserialization
- object-injection
- rce
cve:
- CVE-2026-23524
severity: critical
confidence: medium
status: verified
affected_versions: < 1.7.0
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T08:49:05+08:00'
  notes: 已对照原文与7张图核对：图01 NVD CVE-2026-23524（1.6.3及以下、CVSS 9.8、1.7.0修复、需REVERB_SCALING_ENABLED=true），图02 ReverbServerProvider::register注入PusherPubSubIncomingMessageHandler，图03-05 connect/subscribe/message回调，图06 handle()中unserialize($event['application'])无allowed_classes，图07修复diff为Application::class与metrics分支三类型白名单。卡片原理、触发条件、投递原语、CVE/版本均与原文一致；affected_versions已存在（< 1.7.0）且相符。未验证点：原文未给gadget链，端到端RCE无PoC，卡已标confidence medium；未本机复跑；frontmatter无sources/source_url。
url: /docs/web/php/deserialization/web-php-deserialization-laravel-reverb-redis-unserialize/
draft: false
kb_aliases:
- CVE-2026-23524
- Laravel Reverb 反序列化
- Reverb Redis 反序列化 RCE
- PUBLISH reverb 恶意序列化数据
- Laravel Reverb Redis scaling unserialize
---

## 一句话结论

Laravel Reverb 在启用水平扩展（`REVERB_SCALING_ENABLED=true`）时，会把 Redis `reverb` 频道收到的每条消息交给 `unserialize()`，且未设置 `allowed_classes` 白名单；能向该 Redis 发布消息的攻击者（Redis 常未鉴权）即可让 Reverb 进程反序列化任意已加载的 PHP 类，借助应用内可用的 gadget 链实现远程代码执行（CVE-2026-23524，CVSS 9.8，影响 `< 1.7.0`）。

## 原理

- 扩展模式下，`ReverbServerProvider::register()` 把 `RedisPubSubProvider` 注册为单例，并通过容器 `$app->make(PubSubIncomingMessageHandler::class)` 自动装配接口实现 `PusherPubSubIncomingMessageHandler`，再把后者注入 `RedisPubSubProvider` 的 `messageHandler`。
- `RedisPubSubProvider::connect()` 创建 `RedisSubscribeClient`，在连接成功回调里执行 `subscribe()`：向 Redis 发送 `SUBSCRIBE "reverb"`（频道名取自 `config['scaling']['channel']`，默认 `reverb`），并注册 `message` 事件回调 `fn (string $channel, string $payload) => $this->messageHandler->handle($payload)`。ReactPHP 事件循环把每条 Redis 消息原样送进处理器。
- `PusherPubSubIncomingMessageHandler::handle()` 先 `json_decode($payload, associative: true, flags: JSON_THROW_ON_ERROR)`，随后直接执行 `unserialize($event['application'])`，没有 `allowed_classes` 参数。因此 JSON 中 `application` 字段的任意字符串都会进入 PHP 原生反序列化器，可实例化任意已自动加载的类，并在 `unserialize()` 返回前同步触发 `__wakeup()` / `__destruct()` 等魔术方法。
- 该信任边界的问题在于：Redis Pub/Sub 频道被当作内部可信通道，代码只做 JSON 解析就交给 `unserialize()`；而 Redis 往往未设置密码、监听内网甚至可从纵向移动后的主机访问。攻击者不需要接触 Reverb 的 WebSocket 端口，只要能 `PUBLISH` 到同一频道即可。
- 修复版本在 `unserialize()` 上加了 `['allowed_classes' => [Application::class]]`；`type: metrics` 分支的另一处 `unserialize($event['payload'])` 也加了 `[Application::class, PendingMetric::class, MetricType::class]` 白名单。白名单之外的类型只会得到 `__PHP_Incomplete_Class`，魔术方法链被截断。

## 触发条件

- Laravel Reverb 版本 `< 1.7.0`（原文表述为 1.6.3 及更早）；
- 开启水平扩展：`REVERB_SCALING_ENABLED=true`，且 Reverb 能连上目标 Redis；
- 攻击者具备向该 Redis 发布消息的能力（未授权访问、弱口令、或已拿到内网立足点）；
- 消息发往 `scaling.channel`（默认 `reverb`），JSON 中包含 `application` 字段；`type` 字段不影响第一处 sink 的触发；
- 目标应用/框架中加载了可用于 `__destruct`/`__wakeup` 起点的 gadget 链（Laravel 生态存在公开链，如 phpggc 中的 Laravel 系列），否则只能造成对象注入与类型混乱，未必直接到代码执行。

## 利用步骤

1. 确认目标：探测 Redis（默认 6379）可访问且未鉴权，或从已控主机连接内网 Redis；观察是否存在 Reverb 相关频道/键。
2. 确认 Reverb 开启扩展：向 `reverb` 频道发布无害消息后，观察 Reverb 进程日志或行为；也可从 WebSocket 服务与 Redis 的连接、配置泄露判断。
3. 按目标加载的类构造 PHP 序列化 payload：优先使用 Laravel 已知 gadget 链（可用 phpggc 生成），最终 sink 选择命令执行/文件写入；若应用自带第三方库，可自行审计 `__destruct`/`__wakeup` 起点。
4. 将 payload 作为 JSON 的 `application` 值，向 `reverb` 频道 `PUBLISH`：

```bash
redis-cli -h 10.0.0.1 PUBLISH "reverb" \
  '{"application":"<serialized_payload>","type":"message"}'
```

5. 序列化在 Reverb 进程内同步发生，魔术方法链触发后执行 payload 指定的命令/写文件；通过回连、写入 Web 目录或带外通道确认结果。

## PoC

原文只给出投递原语，未给出可执行的 gadget 链，故端到端 RCE 无 PoC：

```bash
redis-cli -h <redis_host> PUBLISH "reverb" '{"application":"O:...","type":"message"}'
```

其中 `O:...` 需替换为针对目标类环境构造的序列化对象；`application` 必须是字符串，否则 `unserialize()` 得到 `false`。另可构造 `type: metrics` 消息，使 `payload` 字段进入第二处 `unserialize()`，作为备用入口。

## 变体与关联

- 第二处 sink：`metrics` 分支对 `$event['payload']` 同样无白名单反序列化，修复时一并加了 `PendingMetric`/`MetricType` 白名单；当第一处入口不可用（如 `application` 被代理过滤）时可改走该分支。
- 同类信任边界：把 Redis 当作内部消息总线/缓存并直接反序列化其内容的应用（队列 worker、广播、缓存会话）都可能复现同样的“Redis 未授权 → 反序列化”模式。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（gadget 链构造方法）；[[web-php-deserialization-compressed-phar-include-bypass]]（另一类反序列化触发面）。
- 影响边界：成功利用时以 Reverb 进程权限执行代码；即使无可用 gadget，也可造成任意对象实例化、类型混淆与业务逻辑破坏。

## 检测与防御

- 检测：Redis `MONITOR`/慢日志中出现向 `reverb` 频道的 `PUBLISH`，消息体含 `"application"` 且值为 `O:`/`a:` 等 PHP 序列化结构；Reverb 日志出现 `unserialize()` 相关告警或未知类；Redis 出现来自非 Reverb 节点的客户端连接。
- 修复：升级 Laravel Reverb 至 `1.7.0` 及以上，确保两处 `unserialize()` 均带 `allowed_classes` 白名单。
- 加固：为 Redis 设置强密码与 ACL，仅监听回环/私网并做网络隔离；单节点部署可设 `REVERB_SCALING_ENABLED=false` 完全绕过该逻辑；禁止 Redis 暴露到不可信网络。
- 纵深：在应用层避免对消息总线内容使用 `unserialize()`，改用 JSON + 显式字段校验；限制 PHP 进程权限与出网，降低 gadget 链成功后的危害。
