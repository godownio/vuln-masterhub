---
id: defense-detection-ssh-bruteforce-alert-iptables-block
title: ELK 聚合 SSH 失败登录并按阈值分级告警、自动 iptables 封禁
type: scenario
domain: defense
path: defense/detection
technique: ssh-bruteforce-log-alert-autoblock
tags:
- detection
- ssh
- bruteforce
- elk
- elasticsearch
- iptables
- soar
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:51:54+08:00'
  notes: 已对照原文核对：Filebeat/Logstash收集auth.log，Python按1分钟窗口聚合Failed password并按5/10/20分级，≥阈值告警+iptables封禁+白名单+冷却+审计；截图7/8显示钉钉告警与DROP规则。卡片已如实标注原文14次被标高危与≥20阈值矛盾、ES查询实现省略。无组件版本，未设versions
url: /docs/defense/detection/defense-detection-ssh-bruteforce-alert-iptables-block/
draft: false
kb_aliases:
- SSH 暴力破解检测
- ELK SSH 爆破告警
- iptables 自动封禁
- 安全运营闭环
- 失败登录分级告警
---

## 一句话结论

把 `/var/log/auth.log` 集中到 ELK，Python 脚本按 1 分钟窗口对 `Failed password` 按源 IP 聚合，达到 5/10/20 次分别推送低/中/高危告警，高危时调用 iptables 封禁源 IP，并用白名单、冷却时间和审计日志控制误封与告警风暴。

## 原理

sshd 对每次失败认证都会写入一条包含 `Failed password` 和源 IP 的日志。单条失败无法区分用户输错密码和自动化爆破，但在固定时间窗内按源 IP 计数后，高频失败就构成可判定的信号：

- Filebeat 采集 `auth.log`，Logstash 把日志写入 Elasticsearch；
- Python 脚本定期查询最近 1 分钟的 `Failed password` 文档，用 `terms` 聚合 `src_ip.keyword` 得到每个 IP 的失败次数；
- 次数映射为告警级别，通过 Webhook 推送；
- 超过最高阈值时执行 `iptables -I INPUT -s <ip> -j DROP` 阻断；
- 白名单排除内网、网关和管理 IP，冷却窗口抑制重复告警，所有告警/封禁动作写审计日志。

这是“检测 → 分级 → 处置 → 留痕”的最小 SOAR 闭环，适用于自建小规模环境；生产环境应优先用 fail2ban/CrowdSec 等成熟组件，并保留人工复核。

## 触发条件

- sshd 开启密码认证且会记录 `Failed password`（常见的默认配置）；
- Filebeat 有权限读取 `/var/log/auth.log`（该文件常为 640 root:adm，需要调整权限或把 Filebeat 加入 adm 组）；
- Logstash 能从日志中提取 `src_ip`，且 Elasticsearch 中存在可聚合的 `src_ip.keyword` 字段；
- 告警脚本能访问 Elasticsearch，并能以 sudo 执行 iptables；
- 白名单配置正确，源 IP 未被 NAT/代理统一成一个地址。

## 利用步骤

1. 部署 Filebeat，增加 `/var/log/auth.log` 输入并标记 `log_type: ssh_auth`。
2. Logstash 对含 `Failed password` 的日志提取源 IP：

```ruby
if "Failed password" in [message] {
  mutate { add_field => { "attack_type" => "ssh_bruteforce" } }
  grok { match => { "message" => "from %{IP:src_ip}" } }
}
```

3. 日志写入 `secops-*` 索引，确认 `src_ip.keyword` 可聚合。
4. 告警脚本每分钟查询一次并聚合：

```json
{
  "query": {
    "bool": {
      "must": [
        {"match_phrase": {"message": "Failed password"}},
        {"range": {"@timestamp": {"gte": "now-1m"}}}
      ]
    }
  },
  "aggs": {
    "by_src_ip": {"terms": {"field": "src_ip.keyword", "size": 20}}
  }
}
```

5. 按阈值分级：1–4 次不告警，5–9 低危，10–19 中危，≥20 高危；高危推送后执行封禁。
6. 封禁前检查白名单，封禁后写审计日志；同一 IP 10 分钟内只告警一次。

## PoC

模拟失败登录（仅限自有靶机）：

```bash
for i in {1..25}; do
  sshpass -p "wrongpass" ssh -o StrictHostKeyChecking=no wronguser@localhost
done
```

封禁与验证：

```bash
sudo iptables -I INPUT -s <attacker_ip> -j DROP
sudo iptables -L INPUT -n --line-numbers | grep DROP
```

原文的告警脚本节选（ES 查询与钉钉发送函数省略）：

```python
for b in buckets:
    ip, count = b["key"], b["doc_count"]
    level = "高危" if count >= 20 else "中危" if count >= 10 else "低危" if count >= 5 else None
    if not level:
        continue
    if time.time() - last_alert_time.get(ip, 0) < 600:
        continue
    send_dingtalk_alert(f"IP: {ip}, 次数: {count}", level)
    if count >= 20:
        block_ip(ip)
```

需要注意：原文正文的阈值表写的是 `≥20` 为高危，但其演示日志把 14 次失败标成“高危”并执行了封禁，说明脚本/日志版本与文中阈值不一致。落地时应以实际代码和测试结果为准，不要照抄示例数字。

## 变体与关联

- 变体：用 fail2ban、sshguard、CrowdSec 做同类检测与封禁；用 ElastAlert/Elasticsearch Watcher 替代自写 Python 轮询；按 `geoip.country_name` 统计来源国家；把 Windows 安全日志的 4625 事件纳入同一告警管道。
- 关联：[[defense-detection-logstash-nginx-sqli-tagging]]（同一套 ELK 日志平台的 Web 注入检测）；`web/generic/sqli`（原 RuoYi 卡已删除）（另一类可接入同一告警管道的攻击）。
- 不确定点：告警脚本的 ES 查询与钉钉发送实现未给出；原文演示的 14 次高危与阈值表矛盾；iptables 规则只封源 IP，未处理 IPv6、代理池和 NAT 场景。

## 检测与防御

- **阈值与窗口**：按业务和暴露面调整窗口/阈值，先观察一段时间再启用自动封禁；对 5 次以下只记录不告警。
- **白名单与误封**：内网、网关、跳板机、监控和办公出口 IP 必须加入白名单；注意 NAT 后多个用户共享出口 IP，直接封禁可能影响整栋办公网。
- **封禁实现**：优先用 `iptables -m recent`、nftables set 或 fail2ban 的自动过期规则，避免规则无限增长；记录规则编号与过期时间，支持人工解封。
- **权限**：`sudo NOPASSWD` 只授予最小命令集（如固定的 iptables 路径），脚本与 sudoers 文件不可被普通用户改写；审计日志写入独立、只追加的位置。
- **根因防御**：关闭密码登录、强制密钥认证、限制 sshd 暴露面、部署 Fail2ban/堡垒机；对成功登录后的异常行为继续检测，不能只盯失败次数。
