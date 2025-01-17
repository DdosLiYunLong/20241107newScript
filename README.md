脚本简介：

这个脚本主要用于通过 HTTP/2 协议对目标服务器发起高频并行请求，以模拟高流量访问或进行压力测试。它的关键特性包括：

高并发请求：通过多线程和大量自定义的 HTTP/2 帧，快速生成并发送大量请求，从而对目标服务器进行高频访问。
代理支持：从代理列表中随机选取代理进行连接，每个请求使用不同的 IP 地址，有助于绕过基于 IP 的访问限制。
TCP 参数动态调整：定期更改 TCP 拥塞控制算法和其他底层网络参数，使流量特征更难被检测和限制。
动态 HTTP/2 请求头：随机生成和更改 HTTP/2 请求头，模拟真实的用户行为，进一步增加请求的多样性和复杂性。
该脚本适用于进行 HTTP/2 环境下的高并发连接测试，评估目标服务器的处理能力和流量管理策略。

示例命令：
node bypass.js 网站 时间 速率 线程 proxies.txt
