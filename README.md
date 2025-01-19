# ⚡ srun-login ![Go](https://github.com/Sleepstars/SZU-login/workflows/Go/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/Sleepstars/SZU-login)](https://goreportcard.com/report/github.com/Sleepstars/SZU-login) [![Sourcegraph](https://img.shields.io/badge/view%20on-Sourcegraph-brightgreen.svg?logo=sourcegraph)](https://sourcegraph.com/github.com/Sleepstars/SZU-login)

深圳大学校园网 Wi-Fi 登录 / 深澜（srun）校园网模拟登录

2025 年寒假，教学区已经替换掉了老旧的 Dr.com 程序，更换了带有加密的深澜（srun）的程序，这个时候就需要用到这个工具了。

## 开始使用

```bash
# 克隆项目
git clone git@github.com:Sleepstars/SZU-login.git

# 编译项目
go build cmd/srun-login.go

# 模拟登录
./srun-login --username=<REDACTED> --password=<REDACTED>
```

## License

MIT License
