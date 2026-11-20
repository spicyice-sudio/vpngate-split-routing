# VPN Gate 自动选优与分流

在 Linux 落地机上为指定域名选择美国 VPN Gate 出口。Xray 给匹配流量的 IPv4 出站连接设置 `SO_MARK=51888`，Linux 策略路由把它们送入当前健康的 OpenVPN 隧道。其他流量继续使用系统默认出口。示例将 Meta 和 `muse.ai` 分流，支持接入已有的 Xray/VLESS 和可选的 Hysteria 2 服务。

```text
Xray / VLESS ──域名匹配─────────────────┐
Hysteria 2 ─── ACL ──本机 Xray SOCKS5 ──┴─ mark 51888 ── VPN 主线 / 备用 1 / 备用 2
                                                     └─ 无健康 VPN 时走系统出口
```

## 选优和切换

- 每轮同时评测主线、两条现用备用、24 小时内验证过的合格池，并在有足够候选时探索至少 3 个新节点。优先重用健康主备的现有隧道，其他候选通过独立的 `vgscan0` 测试。
- 检查美国出口、Instagram、Threads、Facebook、WhatsApp 和连通性探针。Meta 四站都通过且总体成功率达到 80% 后，按可靠率、HTTPS TTFB 中位数和 512 KiB 下载测速评分。节点来自 [VPN Gate 官方列表](https://www.vpngate.net/en/)。
- 健康主线最短保留 6 小时，新节点至少快 25%（按综合分数）才升级。升级失败时恢复原配置。备用严格按更高分替换，同分保留原连接，并保护正在承载流量的备用。
- 健康检查约每 10 秒并行执行。接口消失或出口国家错误时立即排除，普通探测失败需要连续两轮。当前线路失效后优先采用健康备用，所有已配置 VPN 都失效后才用系统出口。系统出口会看到本机的正常公网 IP。

```text
score = 100 × reliability³ × (0.6 / (median_ttfb_seconds + 0.15)
                           + 0.4 × log2(1 + min(download_mbps, 100)))
```

## 安装

需要带 systemd 和 TUN 的 Linux、Python 3.9+、OpenVPN 2.5+、iproute2、curl、sysctl 和 CA 证书。Debian/Ubuntu 可用 `sudo apt install python3 openvpn iproute2 curl procps ca-certificates`。systemd 服务需要管理隧道和路由的权限。部署前确认 `vgmeta0` 到 `vgmeta2`、`vgscan0`、路由表 51888、51889、51900、51911、51912，以及 IPv4 规则优先级 11981、11982、11990、12000、12100 空闲。

在仓库根目录安装脚本和 unit：

```bash
sudo install -d -m 0755 /usr/local/libexec
sudo install -d -m 0700 /etc/meta-vpngate /var/lib/meta-vpngate
sudo install -m 0755 libexec/*.py /usr/local/libexec/
sudo install -m 0644 systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
```

如能确定落地机正常出站的公网 IPv4，复制 `examples/settings.env.example` 到 `/etc/meta-vpngate/settings.env` 并填写 `VPN_GATE_DIRECT_IPV4`。健康检查会拒绝同一个地址作为 VPN 出口，回退状态也会显示该地址。留空时回退状态的 `exit_ip` 为 `null`。

从 [VPN Gate 官方列表](https://www.vpngate.net/en/) 下载一份美国节点的 OpenVPN 配置，并记录页面显示的节点 IPv4。将下列命令中的文件路径和示例 IPv4 换成实际值。初始化会生成主隧道配置，筛掉外部脚本、插件和路由指令，保留内联 TLS 材料，并禁止 OpenVPN 接管全局默认路由。

```bash
sudo /usr/local/libexec/meta-vpngate-scan.py --seed-profile ./downloaded.ovpn 203.0.113.10
sudo systemctl enable --now meta-vpngate.service meta-vpngate-health.service
sudo systemctl start meta-vpngate-scan.service
sudo systemctl enable --now meta-vpngate-scan.timer meta-vpngate-pool.timer
```

首次扫描为合格备用分配 slot 1 和 2，并启动对应隧道。备用不足时，后续扫描会继续寻找候选。系统重启后，健康服务会启动已有配置的备用实例。扫描默认在北京时间 04:20、10:20、16:20 和 22:20 调度，每次附加最多 3 分钟的随机延迟。

## 接入代理

1. 将 [Xray 配置片段](examples/xray-routing.json) 合并到现有配置中，把 `vless-in` 换成实际入站标签，并将匹配分流的规则放在默认规则前。如果客户端将域名提前解析为 IP，在 VLESS 入站启用 HTTP/TLS/QUIC sniffing，使用 `routeOnly: true`。Xray 进程需要设置 `SO_MARK` 的 Linux 权限，使用 IPv4 出站。按需检查 [Xray 路由规则](https://xtls.github.io/en/config/routing) 和 [socket 配置](https://xtls.github.io/en/config/transports/sockopt.html)。
2. Hysteria 2 和 Xray 在同一台机器上时，可合并 [Hysteria 2 配置片段](examples/hysteria2-routing.yaml)。SOCKS5 绑定在回环地址，并由 Xray 设置标记。两个示例都依赖包含 `meta` 分类的 GeoSite 文件，Hysteria 2 示例中的文件路径可按部署调整。参见 [Hysteria 2 服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#outbounds)。

## 验证

```bash
sudo cat /run/meta-vpngate/status.json
sudo cat /var/lib/meta-vpngate/scan-report.json
ip -4 route get 1.1.1.1 mark 51888
ip -4 route get 1.1.1.1
curl -4 --noproxy '' --socks5-hostname 127.0.0.1:19080 https://1.1.1.1/cdn-cgi/trace
```

隧道健康时，带标记的路由应显示当前选中的 `vgmeta*`，无标记的路由应显示正常网卡。检查 SOCKS 请求返回的 `loc=US` 和状态中的 `exit_ip`。对有域名分流的真实代理流量，用 Xray 日志确认命中了 `vpn-gate-us`。如需只扫描不切换，可运行 `sudo /usr/local/libexec/meta-vpngate-scan.py --dry-run`。该命令仍会建立独立测试隧道并更新扫描报告和候选缓存。手动运行时可通过 `sudo env VPN_GATE_DIRECT_IPV4=实际地址 …` 传入正常出站地址。

离线测试使用 Python 标准库：

```bash
for test in tests/test_*.py; do python3 "$test" || exit 1; done
```
