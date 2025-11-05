# DMPF-PSI

一个基于分布式多点函数（DMPF）的PSI协议实现，同时也支持可更新场景下PSI的实现。

## ⚠️ 警告

**本仓库是一个研究原型**，旨在演示我们的基于DMPF的PSI和UPSI协议的性能并展示其功能，仅应用于实验或研发目的，它并非"生产就绪"版本。

## 🌟 功能特性

### 基于多种DMPF的PSI实现

支持四种DMPF实现方案：
- **DPF DMPF**：基于分布式点函数的基础实现
- **Batch Code DMPF**：批处理编码优化的实现  
- **Big-State DMPF**：大状态管理的实现
- **OKVS DMPF**：基于Oblivious Key-Value Store的实现

### PSI功能扩展
- **PSI**：普通PSI，允许双方计算其集合的交集，而不泄露任何额外信息
- **PSI-CA**：PSI-Cardinality，用于计算两个集合的交集的大小
- **PSI-Sum**：计算交集中元素关联的值的总和

### 基于DMPF的UPSI实现
- 基于DMPF实现的UPSI及UPSI-CA、UPSI-Sum等拓展功能
- 完整的性能测试和正确性验证

### 优化特性
- 离线/在线两阶段优化设计
- 完整的性能测试和正确性验证

## 🛠️ 安装

### 先决条件
- Rust 1.70+
- CMake 3.10+

### 构建项目
```bash
git clone https://github.com/Little-Tier/dmpf-psi.git
cd dmpf-psi-main
cargo build --release
```

## 📊 基准测试
所有基准测试位于benches目录中。

### PSI基准测试
可以在代码中更改**PSI_SET_SIZES**来调整测试集合大小进行基准测试。

- **基础PSI测试：**：
```bash
cargo bench --bench psi_okvs        # 基于OKVS-based DMPF的PSI基准测试
cargo bench --bench psi_big_state   # 基于Big-state DMPF的PSI基准测试  
cargo bench --bench psi_dpf         # 基于DPF-based DMPF的PSI基准测试
cargo bench --bench psi_batch_code  # 基于PBC-based DMPF的PSI基准测试
```

- **PSI扩展功能测试：**
```bash
cargo bench --bench psi_ca_okvs     # 基于OKVS-based DMPF的PSI-CA基准测试
cargo bench --bench psi_sum_okvs    # 基于OKVS-based DMPF的PSI-Sum基准测试
```

### UPSI基准测试
对于如N=2<sup>16</sup>, N<sub>d</sub>=2<sup>6</sup> 的情况，我们希望在输入集总基数达到N的当天运行该协议，而不是模拟所有的2<sup>16</sup>/2<sup>6</sup>=1024天。我们在UPSI的基准测试中模拟的是第1023天到第1024天的更新。

可以在代码中更改**UPSI_TOTAL_SET_SIZES**和**UPSI_DAILY_UPDATE_SIZES**来调整测试总集合大小和更新集合大小进行基准测试。

- **UPSI测试：**
```bash
cargo bench --bench upsi_okvs       # 基于OKVS-based DMPF的UPSI基准测试
cargo bench --bench upsi_ca_okvs    # 基于OKVS-based DMPF的UPSI-CA基准测试
cargo bench --bench upsi_sum_okvs   # 基于OKVS-based DMPF的UPSI-Sum基准测试
```

## 📈 测试结果
上述所有测试结果保存在data目录中，可以查看离线/在线的运行时间、交集计算结果、正确性验证等信息。
