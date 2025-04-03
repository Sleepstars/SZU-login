// Copyright 2021 E99p1ant. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
	log "unknwon.dev/clog/v2"

	"github.com/Sleepstars/SZU-login/pkg/srun"
)

// Config 表示 config.yaml 文件的结构
type Config struct {
	Credentials struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"credentials"`
	Network struct {
		Teaching struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			IP      string `yaml:"ip"`
			AcID    string `yaml:"ac_id"`
		} `yaml:"teaching"`
		Dormitory struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			IP      string `yaml:"ip"`
		} `yaml:"dormitory"`
	} `yaml:"network"`
	Monitor struct {
		Enabled  bool     `yaml:"enabled"`
		Interval int      `yaml:"interval"`
		TestURLs []string `yaml:"test_urls"`
	} `yaml:"monitor"`
	Debug struct {
		Enabled                 bool `yaml:"enabled"`
		VerboseNetworkDetection bool `yaml:"verbose_network_detection"`
		Timeout                 int  `yaml:"timeout"`
	} `yaml:"debug"`
}

// LoadConfig 从 config.yaml 加载配置
func LoadConfig() (*Config, error) {
	// 获取可执行文件目录
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("获取可执行文件路径失败: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// 在可执行文件同一目录下寻找 config.yaml
	configPath := filepath.Join(exeDir, "config.yaml")

	// 如果没找到，尝试当前工作目录
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("获取工作目录失败: %v", err)
		}
		configPath = filepath.Join(wd, "config.yaml")
	}

	// 读取并解析配置文件
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	return &config, nil
}

// CheckInternetConnectivity 检查是否能访问互联网
func isNetworkAccessible(testURLs []string, config *Config) bool {
	timeoutSeconds := 5
	if config.Debug.Enabled && config.Debug.Timeout > 0 {
		timeoutSeconds = config.Debug.Timeout
	}

	for _, url := range testURLs {
		client := createHTTPClientWithIP("", time.Duration(timeoutSeconds)*time.Second)
		client.Timeout = 5 * time.Second
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
	}
	return false
}

// TestNetworkEndpoint 检查特定网络端点是否可达
func TestNetworkEndpoint(urlStr string, ip string, config *Config) bool {
	timeoutSeconds := 5
	if config.Debug.Enabled && config.Debug.Timeout > 0 {
		timeoutSeconds = config.Debug.Timeout
	}

	// 如果指定了IP，则使用它直接连接
	client := createHTTPClientWithIP(ip, time.Duration(timeoutSeconds)*time.Second)

	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[调试] 测试网络端点: %s (IP: %s)", urlStr, ip)
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[调试] 端点测试失败: %v", err)
		}
		return false
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[调试] 读取响应失败: %v", err)
		}
		return false
	}

	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[调试] 端点响应状态: %d", resp.StatusCode)
		log.Info("[调试] 响应体预览: %s", truncateString(string(body), 200))
	}

	return true
}

// IsTeachingNetwork 检查我们是否在教学区网络中
func IsTeachingNetwork(urlStr string, ip string, config *Config) bool {
	return TestNetworkEndpoint(urlStr, ip, config)
}

// IsDormitoryNetwork 检查我们是否在宿舍区网络中
func IsDormitoryNetwork(urlStr string, ip string, config *Config) bool {
	// 从URL中提取基本域名
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[调试] 解析宿舍URL %s 失败: %v", urlStr, err)
		}
		return false
	}

	// 只获取协议和主机部分
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	return TestNetworkEndpoint(baseURL, ip, config)
}

// IsInCampusNetwork 检查我们是否在任何校园网络中
func IsInCampusNetwork(config *Config) bool {
	networks := DetectCampusNetwork(config)

	// 如果检测到教学区或宿舍区网络，我们就在校园网络中
	return networks["teaching"] || networks["dormitory"]
}

// DetectCampusNetwork 检测我们连接的校园网络类型
// 返回一个以网络类型为键、布尔值为值的映射，表示是否检测到该网络
func DetectCampusNetwork(config *Config) map[string]bool {
	result := make(map[string]bool)

	// 首先尝试基于ping的教学区检测
	if config.Network.Teaching.Enabled && config.Network.Teaching.IP != "" {
		teachingPingSuccess := pingIP(config.Network.Teaching.IP, config)
		result["teaching"] = teachingPingSuccess

		if teachingPingSuccess {
			log.Info("检测到教学区网络（ping成功）")
		} else if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			// 如果ping失败，则回退到HTTP检测
			log.Info("[调试] 教学网络ping失败，回退到HTTP检测")
			teachingDetected := IsTeachingNetwork(config.Network.Teaching.URL, config.Network.Teaching.IP, config)

			if teachingDetected {
				result["teaching"] = true
				log.Info("检测到教学区网络（HTTP成功）")
			}
		}
	} else if config.Network.Teaching.Enabled {
		// 未提供IP，使用HTTP检测
		teachingDetected := IsTeachingNetwork(config.Network.Teaching.URL, config.Network.Teaching.IP, config)
		result["teaching"] = teachingDetected
		if teachingDetected {
			log.Info("检测到教学区网络")
		}
	}

	// 使用ping检查宿舍网络
	if config.Network.Dormitory.Enabled && config.Network.Dormitory.IP != "" {
		dormitoryPingSuccess := pingIP(config.Network.Dormitory.IP, config)
		result["dormitory"] = dormitoryPingSuccess

		if dormitoryPingSuccess {
			log.Info("检测到宿舍区网络（ping成功）")
		} else if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			// 如果ping失败，则回退到HTTP检测
			log.Info("[调试] 宿舍网络ping失败，回退到HTTP检测")
			dormitoryDetected := IsDormitoryNetwork(config.Network.Dormitory.URL, config.Network.Dormitory.IP, config)

			if dormitoryDetected {
				result["dormitory"] = true
				log.Info("检测到宿舍区网络（HTTP成功）")
			}
		}
	} else if config.Network.Dormitory.Enabled {
		// 未提供IP，使用HTTP检测
		dormitoryDetected := IsDormitoryNetwork(config.Network.Dormitory.URL, config.Network.Dormitory.IP, config)
		result["dormitory"] = dormitoryDetected
		if dormitoryDetected {
			log.Info("检测到宿舍区网络")
		}
	}

	return result
}

// LoginTeachingArea 尝试登录教学区网络
func LoginTeachingArea(config *Config) error {
	// 使用默认参数创建客户端
	client := srun.NewClient(config.Network.Teaching.URL,
		config.Credentials.Username,
		config.Credentials.Password)

	// 如果指定了自定义IP，配置客户端使用它
	if config.Network.Teaching.IP != "" {
		log.Info("使用自定义IP %s 登录教学区", config.Network.Teaching.IP)
		client.SetServerIP(config.Network.Teaching.IP)
	}

	// 如果在配置中提供了AC-ID，则设置它
	if config.Network.Teaching.AcID != "" {
		log.Info("使用自定义AC-ID %s 登录教学区", config.Network.Teaching.AcID)
		client.SetAcID(config.Network.Teaching.AcID)
	}

	challengeResp, err := client.GetChallenge()
	if err != nil {
		return fmt.Errorf("获取challenge失败: %v", err)
	}

	challenge := challengeResp.Challenge
	log.Trace("Challenge: %q", challenge)

	portalResp, err := client.Portal(challenge)
	if err != nil {
		return fmt.Errorf("portal调用失败: %v", err)
	}

	if portalResp.Error != "ok" && portalResp.St != 1 {
		return fmt.Errorf("登录失败: %s", portalResp.ErrorMsg)
	}

	log.Info("成功登录教学区网络")
	return nil
}

// LoginDormitoryArea 尝试登录宿舍区网络
func LoginDormitoryArea(config *Config) error {
	dormURL := config.Network.Dormitory.URL

	// 对于宿舍区，我们需要使用用户凭据作为参数发起GET请求
	params := url.Values{}
	params.Add("user_account", config.Credentials.Username)
	params.Add("user_password", config.Credentials.Password)

	requestURL := dormURL + "?" + params.Encode()

	timeoutSeconds := 10
	if config.Debug.Enabled && config.Debug.Timeout > 0 {
		timeoutSeconds = config.Debug.Timeout
	}
	client := createHTTPClientWithIP(config.Network.Dormitory.IP, time.Duration(timeoutSeconds)*time.Second)

	resp, err := client.Get(requestURL)
	if err != nil {
		return fmt.Errorf("登录宿舍区网络失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	// 简单检查登录是否成功
	if strings.Contains(string(body), "success") || resp.StatusCode == http.StatusOK {
		log.Info("成功登录宿舍区网络")
		return nil
	}

	return fmt.Errorf("登录宿舍区网络失败")
}

// truncateString 如果字符串长度超过maxLen，则截断它
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// pingIP 使用系统ping命令测试IP地址是否可达
func pingIP(ip string, config *Config) bool {
	if ip == "" {
		return false
	}

	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[调试] 使用ping测试IP连接性: %s", ip)
	}

	// 为ping命令设置超时
	timeoutSeconds := 2
	if config.Debug.Enabled && config.Debug.Timeout > 0 && config.Debug.Timeout < 5 {
		timeoutSeconds = config.Debug.Timeout
	}

	// 创建带有超时和count=1（只ping一次）的ping命令
	cmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSeconds), ip)

	// 运行命令
	err := cmd.Run()

	// 检查ping是否成功
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[调试] 对 %s 的ping失败: %v", ip, err)
		}
		return false
	}

	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[调试] 对 %s 的ping成功", ip)
	}

	return true
}

// ConcurrentLogin 尝试同时登录两个网络
func ConcurrentLogin(config *Config, networks map[string]bool) bool {
	log.Info("尝试同时登录所有可用网络")

	// 创建结果通道
	teachingResult := make(chan error, 1)
	dormitoryResult := make(chan error, 1)

	// 如果检测到教学区网络，则在goroutine中尝试登录
	if networks["teaching"] {
		go func() {
			log.Info("开始尝试教学区网络登录")
			err := LoginTeachingArea(config)
			teachingResult <- err
		}()
	} else {
		// 未检测到，立即发送错误
		teachingResult <- fmt.Errorf("未检测到教学区网络")
	}

	// 如果检测到宿舍区网络，则在goroutine中尝试登录
	if networks["dormitory"] {
		go func() {
			log.Info("开始尝试宿舍区网络登录")
			err := LoginDormitoryArea(config)
			dormitoryResult <- err
		}()
	} else {
		// 未检测到，立即发送错误
		dormitoryResult <- fmt.Errorf("未检测到宿舍区网络")
	}

	// 等待结果
	teachingErr := <-teachingResult
	dormitoryErr := <-dormitoryResult

	// 检查结果
	teachingSuccess := teachingErr == nil
	dormitorySuccess := dormitoryErr == nil

	if teachingSuccess {
		log.Info("教学区登录成功")
	} else if networks["teaching"] {
		log.Error("教学区登录失败: %v", teachingErr)
	}

	if dormitorySuccess {
		log.Info("宿舍区登录成功")
	} else if networks["dormitory"] {
		log.Error("宿舍区登录失败: %v", dormitoryErr)
	}

	// 如果任何登录成功，则返回true
	return teachingSuccess || dormitorySuccess
}

// createHTTPClientWithIP 创建一个将请求解析到特定IP的HTTP客户端（如果提供了IP）
func createHTTPClientWithIP(ip string, timeout time.Duration) *http.Client {
	client := &http.Client{
		Timeout: timeout,
	}

	// 如果指定了IP，使用带有自定义拨号器的Transport，该拨号器解析到该IP
	if ip != "" {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// 从addr中提取主机和端口
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					// 如果地址中没有端口，使用默认的HTTP/HTTPS端口
					if strings.Contains(err.Error(), "missing port") {
						if strings.HasPrefix(addr, "https") {
							port = "443"
						} else {
							port = "80"
						}
					} else {
						return nil, err
					}
				}

				// 使用自定义IP而不是解析主机名
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		}

		client.Transport = transport
	}

	return client
}

func main() {
	defer log.Stop()
	err := log.NewConsole()
	if err != nil {
		panic(err)
	}

	// 为向后兼容性而设置的命令行标志
	cmdHost := flag.String("host", "", "主机URL（覆盖配置）")
	cmdUsername := flag.String("username", "", "用户名（覆盖配置）")
	cmdPassword := flag.String("password", "", "密码（覆盖配置）")
	cmdTeachingIP := flag.String("teaching-ip", "", "教学区服务器IP（覆盖配置）")
	cmdDormitoryIP := flag.String("dormitory-ip", "", "宿舍区服务器IP（覆盖配置）")
	flag.Parse()

	// 加载配置
	config, err := LoadConfig()
	if err != nil {
		log.Warn("加载配置失败: %v", err)
		log.Warn("将尝试使用提供的命令行参数（如果有）")

		// 如果配置加载失败，确保我们有命令行参数
		if *cmdUsername == "" || *cmdPassword == "" {
			log.Fatal("未提供凭据。请创建config.yaml文件或提供--username和--password标志")
		}

		// 从命令行参数创建最小配置
		config = &Config{}
		config.Credentials.Username = *cmdUsername
		config.Credentials.Password = *cmdPassword

		if *cmdHost != "" {
			// 根据主机猜测网络类型
			if strings.Contains(*cmdHost, "szu.edu.cn") {
				config.Network.Teaching.Enabled = true
				config.Network.Teaching.URL = *cmdHost
			} else {
				config.Network.Dormitory.Enabled = true
				config.Network.Dormitory.URL = *cmdHost
			}
		} else {
			// 默认为教学网络
			config.Network.Teaching.Enabled = true
			config.Network.Teaching.URL = "https://net.szu.edu.cn/"
		}

		// 默认监控设置
		config.Monitor.Enabled = false
	}

	// 如果提供了命令行参数，则覆盖配置
	if *cmdUsername != "" {
		config.Credentials.Username = *cmdUsername
	}
	if *cmdPassword != "" {
		config.Credentials.Password = *cmdPassword
	}
	if *cmdHost != "" {
		// 确定是教学区还是宿舍区URL
		if strings.Contains(*cmdHost, "szu.edu.cn") {
			config.Network.Teaching.URL = *cmdHost
		} else {
			config.Network.Dormitory.URL = *cmdHost
		}
	}
	if *cmdTeachingIP != "" {
		config.Network.Teaching.IP = *cmdTeachingIP
	}
	if *cmdDormitoryIP != "" {
		config.Network.Dormitory.IP = *cmdDormitoryIP
	}

	log.Info("深圳大学网络登录工具")
	log.Info("用户名: %s", config.Credentials.Username)

	// 单次登录或持续监控
	if config.Monitor.Enabled {
		log.Info("启动持续网络监控")
		log.Info("每 %d 秒检查一次互联网连接", config.Monitor.Interval)

		// 首次检查
		if isNetworkAccessible(config.Monitor.TestURLs, config) {
			log.Trace("互联网可访问，无需登录")
		} else {
			log.Info("互联网不可访问，检查校园网络...")

			// 检测校园网络
			networks := DetectCampusNetwork(config)

			// 只有当我们在校园网络中时才继续
			if networks["teaching"] || networks["dormitory"] {
				log.Info("检测到校园网络，尝试登录...")

				// 尝试并行登录
				loggedIn := ConcurrentLogin(config, networks)

				if !loggedIn {
					log.Error("所有登录尝试都失败了")
				}
			} else {
				log.Error("未检测到校园网络。您是否已连接到深大网络？")
			}
		}

		// 持续监控
		for {
			// 如果已经连接到互联网，则跳过登录
			if isNetworkAccessible(config.Monitor.TestURLs, config) {
				log.Trace("互联网可访问，无需登录")
				time.Sleep(time.Duration(config.Monitor.Interval) * time.Second)
				continue
			}

			log.Info("互联网不可访问，检查校园网络...")

			// 检测校园网络
			networks := DetectCampusNetwork(config)

			// 只有当我们在校园网络中时才继续
			if networks["teaching"] || networks["dormitory"] {
				log.Info("检测到校园网络，尝试登录...")

				// 尝试并行登录
				loggedIn := ConcurrentLogin(config, networks)

				if !loggedIn {
					log.Error("所有登录尝试都失败了")
				}
			} else {
				log.Error("未检测到校园网络。您是否已连接到深大网络？")
			}

			time.Sleep(time.Duration(config.Monitor.Interval) * time.Second)
		}
	} else {
		// 单次登录尝试

		// 检测校园网络
		networks := DetectCampusNetwork(config)

		// 只有当我们在校园网络中时才继续
		if networks["teaching"] || networks["dormitory"] {
			log.Info("检测到校园网络，尝试登录...")

			// 尝试并行登录
			loggedIn := ConcurrentLogin(config, networks)

			if !loggedIn {
				log.Error("所有登录尝试都失败了")
			}
		} else {
			log.Error("未检测到校园网络。您是否已连接到深大网络？")
		}
	}
}
