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

// Config represents the structure of the config.yaml file
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
		Enabled               bool `yaml:"enabled"`
		VerboseNetworkDetection bool `yaml:"verbose_network_detection"`
		Timeout               int  `yaml:"timeout"`
	} `yaml:"debug"`
}

// LoadConfig loads configuration from config.yaml
func LoadConfig() (*Config, error) {
	// Get the executable directory
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	
	// Look for config.yaml in the same directory as the executable
	configPath := filepath.Join(exeDir, "config.yaml")
	
	// If not found, try current working directory
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %v", err)
		}
		configPath = filepath.Join(wd, "config.yaml")
	}
	
	// Read and parse config file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	
	return &config, nil
}

// CheckInternetConnectivity checks if we can access the internet
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

// TestNetworkEndpoint checks if a specific network endpoint is reachable
func TestNetworkEndpoint(urlStr string, ip string, config *Config) bool {
	timeoutSeconds := 5
	if config.Debug.Enabled && config.Debug.Timeout > 0 {
		timeoutSeconds = config.Debug.Timeout
	}
	
	// If IP is specified, use it for direct connection
	client := createHTTPClientWithIP(ip, time.Duration(timeoutSeconds)*time.Second)
	
	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[Debug] Testing network endpoint: %s (IP: %s)", urlStr, ip)
	}
	
	resp, err := client.Get(urlStr)
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[Debug] Endpoint test failed: %v", err)
		}
		return false
	}
	
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[Debug] Failed to read response: %v", err)
		}
		return false
	}
	
	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[Debug] Endpoint response status: %d", resp.StatusCode)
		log.Info("[Debug] Response body preview: %s", truncateString(string(body), 200))
	}
	
	return true
}

// IsTeachingNetwork checks if we're in teaching area network
func IsTeachingNetwork(urlStr string, ip string, config *Config) bool {
	return TestNetworkEndpoint(urlStr, ip, config)
}

// IsDormitoryNetwork checks if we're in dormitory area network
func IsDormitoryNetwork(urlStr string, ip string, config *Config) bool {
	// Extract the base domain from the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[Debug] Failed to parse dormitory URL %s: %v", urlStr, err)
		}
		return false
	}
	
	// Get just the scheme and host
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	return TestNetworkEndpoint(baseURL, ip, config)
}

// IsInCampusNetwork checks if we're in any campus network
func IsInCampusNetwork(config *Config) bool {
	networks := DetectCampusNetwork(config)
	
	// If either teaching or dormitory network is detected, we're in campus network
	return networks["teaching"] || networks["dormitory"]
}

// DetectCampusNetwork detects the type of campus network we're connected to
// Returns a map with network types as keys and boolean values indicating if they are detected
func DetectCampusNetwork(config *Config) map[string]bool {
	result := make(map[string]bool)
	
	// First try ping-based detection for teaching area
	if config.Network.Teaching.Enabled && config.Network.Teaching.IP != "" {
		teachingPingSuccess := pingIP(config.Network.Teaching.IP, config)
		result["teaching"] = teachingPingSuccess
		
		if teachingPingSuccess {
			log.Info("Detected teaching area network (ping success)")
		} else if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			// Fall back to HTTP detection if ping fails
			log.Info("[Debug] Ping failed for teaching network, falling back to HTTP detection")
			teachingDetected := IsTeachingNetwork(config.Network.Teaching.URL, config.Network.Teaching.IP, config)
			
			if teachingDetected {
				result["teaching"] = true
				log.Info("Detected teaching area network (HTTP success)")
			}
		}
	} else if config.Network.Teaching.Enabled {
		// No IP provided, use HTTP detection
		teachingDetected := IsTeachingNetwork(config.Network.Teaching.URL, config.Network.Teaching.IP, config)
		result["teaching"] = teachingDetected
		if teachingDetected {
			log.Info("Detected teaching area network")
		}
	}
	
	// Check dormitory network with ping
	if config.Network.Dormitory.Enabled && config.Network.Dormitory.IP != "" {
		dormitoryPingSuccess := pingIP(config.Network.Dormitory.IP, config)
		result["dormitory"] = dormitoryPingSuccess
		
		if dormitoryPingSuccess {
			log.Info("Detected dormitory area network (ping success)")
		} else if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			// Fall back to HTTP detection if ping fails
			log.Info("[Debug] Ping failed for dormitory network, falling back to HTTP detection")
			dormitoryDetected := IsDormitoryNetwork(config.Network.Dormitory.URL, config.Network.Dormitory.IP, config)
			
			if dormitoryDetected {
				result["dormitory"] = true
				log.Info("Detected dormitory area network (HTTP success)")
			}
		}
	} else if config.Network.Dormitory.Enabled {
		// No IP provided, use HTTP detection
		dormitoryDetected := IsDormitoryNetwork(config.Network.Dormitory.URL, config.Network.Dormitory.IP, config)
		result["dormitory"] = dormitoryDetected
		if dormitoryDetected {
			log.Info("Detected dormitory area network")
		}
	}
	
	return result
}

// LoginTeachingArea attempts to login to teaching area network
func LoginTeachingArea(config *Config) error {
	// Create client with default parameters
	client := srun.NewClient(config.Network.Teaching.URL, 
		config.Credentials.Username, 
		config.Credentials.Password)
	
	// If a custom IP is specified, configure the client to use it
	if config.Network.Teaching.IP != "" {
		log.Info("Using custom IP %s for teaching area login", config.Network.Teaching.IP)
		client.SetServerIP(config.Network.Teaching.IP)
	}
	
	// Set AC-ID if provided in config
	if config.Network.Teaching.AcID != "" {
		log.Info("Using custom AC-ID %s for teaching area login", config.Network.Teaching.AcID)
		client.SetAcID(config.Network.Teaching.AcID)
	}
	
	challengeResp, err := client.GetChallenge()
	if err != nil {
		return fmt.Errorf("failed to get challenge: %v", err)
	}
	
	challenge := challengeResp.Challenge
	log.Trace("Challenge: %q", challenge)
	
	portalResp, err := client.Portal(challenge)
	if err != nil {
		return fmt.Errorf("failed to portal: %v", err)
	}
	
	if portalResp.Error != "ok" && portalResp.St != 1 {
		return fmt.Errorf("login failed: %s", portalResp.ErrorMsg)
	}
	
	log.Info("Successfully logged in to teaching area network")
	return nil
}

// LoginDormitoryArea attempts to login to dormitory area network
func LoginDormitoryArea(config *Config) error {
	dormURL := config.Network.Dormitory.URL
	
	// For dormitory, we need to make a GET request with user credentials as parameters
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
		return fmt.Errorf("failed to login to dormitory network: %v", err)
	}
	defer resp.Body.Close()
	
	// Check response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}
	
	// Simple check if login was successful
	if strings.Contains(string(body), "success") || resp.StatusCode == http.StatusOK {
		log.Info("Successfully logged in to dormitory area network")
		return nil
	}
	
	return fmt.Errorf("login to dormitory area network failed")
}

// truncateString truncates a string if it's longer than maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// pingIP tests if an IP address is reachable using system ping command
func pingIP(ip string, config *Config) bool {
	if ip == "" {
		return false
	}
	
	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[Debug] Testing IP connectivity with ping: %s", ip)
	}
	
	// Setting a timeout for the ping command
	timeoutSeconds := 2
	if config.Debug.Enabled && config.Debug.Timeout > 0 && config.Debug.Timeout < 5 {
		timeoutSeconds = config.Debug.Timeout
	}
	
	// Create ping command with timeout and count=1 (just one ping)
	cmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSeconds), ip)
	
	// Run the command
	err := cmd.Run()
	
	// Check if ping was successful
	if err != nil {
		if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
			log.Info("[Debug] Ping to %s failed: %v", ip, err)
		}
		return false
	}
	
	if config.Debug.Enabled && config.Debug.VerboseNetworkDetection {
		log.Info("[Debug] Ping to %s successful", ip)
	}
	
	return true
}

// ConcurrentLogin attempts to login to both networks concurrently
func ConcurrentLogin(config *Config, networks map[string]bool) bool {
	log.Info("Attempting concurrent login to all available networks")
	
	// Create channels for results
	teachingResult := make(chan error, 1)
	dormitoryResult := make(chan error, 1)
	
	// Try teaching area login in a goroutine if detected
	if networks["teaching"] {
		go func() {
			log.Info("Starting teaching network login attempt")
			err := LoginTeachingArea(config)
			teachingResult <- err
		}()
	} else {
		// Not detected, send an error immediately
		teachingResult <- fmt.Errorf("teaching network not detected")
	}
	
	// Try dormitory login in a goroutine if detected
	if networks["dormitory"] {
		go func() {
			log.Info("Starting dormitory network login attempt")
			err := LoginDormitoryArea(config)
			dormitoryResult <- err
		}()
	} else {
		// Not detected, send an error immediately
		dormitoryResult <- fmt.Errorf("dormitory network not detected")
	}
	
	// Wait for results
	teachingErr := <-teachingResult
	dormitoryErr := <-dormitoryResult
	
	// Check results
	teachingSuccess := teachingErr == nil
	dormitorySuccess := dormitoryErr == nil
	
	if teachingSuccess {
		log.Info("Teaching area login successful")
	} else if networks["teaching"] {
		log.Error("Teaching area login failed: %v", teachingErr)
	}
	
	if dormitorySuccess {
		log.Info("Dormitory area login successful")
	} else if networks["dormitory"] {
		log.Error("Dormitory area login failed: %v", dormitoryErr)
	}
	
	// Return true if any login was successful
	return teachingSuccess || dormitorySuccess
}

// createHTTPClientWithIP creates an HTTP client that resolves to a specific IP if provided
func createHTTPClientWithIP(ip string, timeout time.Duration) *http.Client {
	client := &http.Client{
		Timeout: timeout,
	}
	
	// If IP is specified, use a custom Transport with a Dialer that resolves to that IP
	if ip != "" {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Extract host and port from addr
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					// If no port in address, use default HTTP/HTTPS ports
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
				
				// Use the custom IP instead of resolving the hostname
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
	
	// Command line flags for backwards compatibility
	cmdHost := flag.String("host", "", "Host URL (overrides config)")
	cmdUsername := flag.String("username", "", "Username (overrides config)")
	cmdPassword := flag.String("password", "", "Password (overrides config)")
	cmdTeachingIP := flag.String("teaching-ip", "", "Teaching area server IP (overrides config)")
	cmdDormitoryIP := flag.String("dormitory-ip", "", "Dormitory area server IP (overrides config)")
	flag.Parse()
	
	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		log.Warn("Failed to load config: %v", err)
		log.Warn("Will try to use command line arguments if provided")
		
		// If config loading failed, make sure we have command line args
		if *cmdUsername == "" || *cmdPassword == "" {
			log.Fatal("No credentials provided. Either create a config.yaml file or provide --username and --password flags")
		}
		
		// Create minimal config from command line args
		config = &Config{}
		config.Credentials.Username = *cmdUsername
		config.Credentials.Password = *cmdPassword
		
		if *cmdHost != "" {
			// Guess network type based on host
			if strings.Contains(*cmdHost, "szu.edu.cn") {
				config.Network.Teaching.Enabled = true
				config.Network.Teaching.URL = *cmdHost
			} else {
				config.Network.Dormitory.Enabled = true
				config.Network.Dormitory.URL = *cmdHost
			}
		} else {
			// Default to teaching network
			config.Network.Teaching.Enabled = true
			config.Network.Teaching.URL = "https://net.szu.edu.cn/"
		}
		
		// Default monitor settings
		config.Monitor.Enabled = false
	}
	
	// Override config with command line args if provided
	if *cmdUsername != "" {
		config.Credentials.Username = *cmdUsername
	}
	if *cmdPassword != "" {
		config.Credentials.Password = *cmdPassword
	}
	if *cmdHost != "" {
		// Determine if it's teaching or dormitory URL
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
	
	log.Info("SZU Network Login Tool")
	log.Info("Username: %s", config.Credentials.Username)
	
	// Single login or continuous monitoring
	if config.Monitor.Enabled {
		log.Info("Starting continuous network monitoring")
		log.Info("Checking internet connectivity every %d seconds", config.Monitor.Interval)
		
		// First check
		if isNetworkAccessible(config.Monitor.TestURLs, config) {
			log.Trace("Internet is accessible, no login needed")
		} else {
			log.Info("Internet not accessible, checking campus network...")
			
			// Detect campus networks
			networks := DetectCampusNetwork(config)
			
			// Only proceed if we're in a campus network
			if networks["teaching"] || networks["dormitory"] {
				log.Info("Campus network detected, attempting login...")
				
				// Try concurrent login
				loggedIn := ConcurrentLogin(config, networks)
				
				if !loggedIn {
					log.Error("All login attempts failed")
				}
			} else {
				log.Error("No campus network detected. Are you connected to SZU network?")
			}
		}
		
		// Continuous monitoring
		for {
			// Skip login if already connected to internet
			if isNetworkAccessible(config.Monitor.TestURLs, config) {
				log.Trace("Internet is accessible, no login needed")
				time.Sleep(time.Duration(config.Monitor.Interval) * time.Second)
				continue
			}
			
			log.Info("Internet not accessible, checking campus network...")
			
			// Detect campus networks
			networks := DetectCampusNetwork(config)
			
			// Only proceed if we're in a campus network
			if networks["teaching"] || networks["dormitory"] {
				log.Info("Campus network detected, attempting login...")
				
				// Try concurrent login
				loggedIn := ConcurrentLogin(config, networks)
				
				if !loggedIn {
					log.Error("All login attempts failed")
				}
			} else {
				log.Error("No campus network detected. Are you connected to SZU network?")
			}
			
			time.Sleep(time.Duration(config.Monitor.Interval) * time.Second)
		}
	} else {
		// Single login attempt
		
		// Detect campus networks
		networks := DetectCampusNetwork(config)
		
		// Only proceed if we're in a campus network
		if networks["teaching"] || networks["dormitory"] {
			log.Info("Campus network detected, attempting login...")
			
			// Try concurrent login
			loggedIn := ConcurrentLogin(config, networks)
			
			if !loggedIn {
				log.Error("All login attempts failed")
			}
		} else {
			log.Error("No campus network detected. Are you connected to SZU network?")
		}
	}
}
