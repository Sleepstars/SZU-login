# ⚡ srun-login ![Go](https://github.com/Sleepstars/SZU-login/workflows/Go/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/Sleepstars/SZU-login)](https://goreportcard.com/report/github.com/Sleepstars/SZU-login) [![Sourcegraph](https://img.shields.io/badge/view%20on-Sourcegraph-brightgreen.svg?logo=sourcegraph)](https://sourcegraph.com/github.com/Sleepstars/SZU-login)

深圳大学校园网 Wi-Fi 登录 / 深澜（srun）校园网模拟登录

2025 年寒假，教学区已经替换掉了老旧的 Dr.com 程序，更换了带有加密的深澜（srun）的程序，这个时候就需要用到这个工具了。

## 新特性

- ✨ 支持 `config.yaml` 配置文件，无需在命令行中指定账号密码
- ✨ 可指定服务器IP地址，解决DNS解析问题
- ✨ 自动检测并适配教学区和宿舍区网络
- ✨ 支持持续监控和自动重连功能

## 开始使用

### 使用配置文件（推荐）

1. 克隆项目
```bash
git clone git@github.com:Sleepstars/SZU-login.git
```

2. 编辑 `config.yaml` 文件
```yaml
# 用户凭证
credentials:
  username: "123"  # 校园卡账号
  password: "456"  # 校园卡密码

# 网络环境配置
network:
  # 教学区网络配置（深澜系统）
  teaching:
    enabled: true
    url: "https://net.szu.edu.cn/"
    ip: "198.18.6.157"  # 可选：指定服务器IP，防止DNS解析问题
  
  # 宿舍区网络配置
  dormitory:
    enabled: true
    url: "http://172.30.255.42:801/eportal/portal/login/"
    ip: ""  # 可选：指定服务器IP

# 监控配置
monitor:
  enabled: true  # 是否启用持续监控
  interval: 60   # 检查间隔（秒）
  test_urls:     # 用于测试网络连通性的URL
    - "https://www.baidu.com"
```

3. 编译项目
```bash
go build cmd/srun-login.go
```

4. 运行程序（使用配置文件）
```bash
./srun-login
```

### 命令行参数（兼容原有用法）

```bash
# 基本用法
./srun-login --username=<REDACTED> --password=<REDACTED>

# 指定服务器IP地址
./srun-login --username=<REDACTED> --password=<REDACTED> --teaching-ip=198.18.6.157
```

### 同时支持的命令行参数

```
--host              指定登录服务器URL
--username          指定用户名
--password          指定密码
--teaching-ip       指定教学区服务器IP
--dormitory-ip      指定宿舍区服务器IP
```

欢迎查看我的博客观看详细使用方法：[Sleepstars 的记录室](https://blog.sleepstars.net/archives/shen-zhen-da-xue-jiao-xue-qu-xiao-yuan-wang-windows-zi-dong-deng-lu-xin-shou-xiang-xi-lie-er)

## License

MIT License
