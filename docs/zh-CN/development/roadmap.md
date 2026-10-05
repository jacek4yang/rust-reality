# 路线图

简体中文 | [English](../../en/development/roadmap.md)

rust-reality 分为三个经过验证的阶段演进。每个阶段先建立稳定基线，再进入下一阶段。

项目保留一个公网兼容边界：VLESS + REALITY 行为必须兼容当前的 Xray-core 客户端。
内部实现可以持续演进，但正确性、互操作、流量行为和受保护性能指标不得退化。

## 配置兼容

当前有效的 rust-reality 服务端 JSON 配置在本路线图内保持有效，不应要求重写部署配置。

新能力确实需要新信息时，可以增加可选配置，但已有部署的含义保持不变。
可行时，运行时调优仍应自动推导。

## 第一阶段：LINE → LANDING 可靠性

跟踪：[#253](https://github.com/jacek4yang/rust-reality/issues/253)

首先为现有 LINE → LANDING 路径建立可用于生产的可靠性基线。

重点是当前 NXR/Handoff 的稳定性、长连接存活、多 LINE 压力、过载行为、可观测性和
防止回归。本阶段不扩展更广泛的协议或客户端能力。

只有该基线通过正确性、互操作、故障、持续运行、资源和性能验证后，才开始第二阶段。

## 第二阶段：统一的 rust-reality 客户端

跟踪：[#254](https://github.com/jacek4yang/rust-reality/issues/254)

将 rust-reality-client 吸收到本仓库，使客户端成为共享 rust-reality 内核的正式角色。

支持单 LINE 和灵活的多 LINE 使用方式，包括由不同本地入站独立选择 LINE 或 LINE 组。
连接各 LINE 的公网协议仍为标准 VLESS + REALITY；客户端无需知道选中的 LINE 后续使用
直连、NXR、Handoff 还是 LANDING。

只有单 LINE 和多 LINE 客户端均稳定、可互操作、能容错，并相对第一阶段基线通过性能
验证后，才开始第三阶段。

## 第三阶段：统一的高性能传输内核

跟踪：[#255](https://github.com/jacek4yang/rust-reality/issues/255)

完成向通用高性能内核的演进，覆盖客户端、LINE、LANDING、直连、NXR 和 Handoff 部署。

本阶段负责较大的传输演进：TCP 和 UDP 流支持、优化的 LINE → LANDING 传输、
多 LINE/多 LANDING、长连接韧性、连接复用、自适应传输、资源效率，以及经过测量验证的
内核和数据路径优化。

具体实现由第一、二阶段获得的证据决定，不提前锁定方案。

## 验证与部署

每个阶段必须通过自身的自动化测试、互操作检查、故障测试、持续运行测试、资源压力测试
和受保护性能门禁，才能成为下一阶段的基线。

第三阶段通过验证后，生产部署仍分步推进：

1. 部署经过验证的 LANDING；
2. 单个 LINE 灰度验证；
3. 扩大 LINE 部署；
4. rust-reality 客户端单 LINE 模式；
5. 多 LINE 客户端；
6. 扩大生产使用。

任一部署步骤都可以独立停止或回滚，无需重写配置。
