package farcasterd

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"probely.com/farcaster/agent"
	"probely.com/farcaster/control"
	"probely.com/farcaster/netutils"
	"probely.com/farcaster/settings"
	"probely.com/farcaster/system"
)

const (
	maxConnTries = 3

	// Environment variable name for the API (old name) and AGENT tokens.
	envOldTokenName = "FARCASTER_API_TOKEN"
	envTokenName    = "FARCASTER_AGENT_TOKEN"
	envAPIURLName   = "FARCASTER_API_URL"
)

type agentConfig struct {
	token         string
	apiURLs       []string
	checkToken    bool
	controlAPI    string
	group         string
	showVers      bool
	logPath       string
	debug         bool
	apiURL        string
	ipv6          bool
	proxyUseNames bool
	dumpDir       string
	ifaceName     string
}

var (
	appCfg agentConfig

	defaultAPIURLs = []string{
		"https://api.eu.probely.com",
		"https://api.us.probely.com",
		"https://api.au.probely.com",
	}
)

func parseConfig(cfg *agentConfig) error {
	token := getToken(cfg.token)
	// If the control API is enabled, we don't need a token.
	if cfg.controlAPI == "" && token == "" {
		return fmt.Errorf("error: --token argument or %s environment variable is required", envTokenName)
	}
	cfg.token = strings.TrimSpace(token)
	cfg.apiURLs = append(cfg.apiURLs, getAPIURLs(cfg.apiURL)...)
	return nil
}

var rootCmd = &cobra.Command{
	Use:   filepath.Base(os.Args[0]),
	Short: settings.Name + " creates a VPN to Probely",
	Run: func(cmd *cobra.Command, args []string) {
		if appCfg.showVers {
			fmt.Fprintf(os.Stderr, "%s version %s (%s) on %s %s\n",
				settings.Name, settings.Version, settings.Commit, runtime.GOOS, runtime.GOARCH)
			os.Exit(0)
		}
		if err := parseConfig(&appCfg); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		runAgent(appCfg)
	},
}

func init() {
	var apiListener string
	if runtime.GOOS == "windows" {
		apiListener = "Windows named pipe"
	} else {
		apiListener = "Unix socket"
	}
	rootCmd.PersistentFlags().StringVarP(&appCfg.token, "token", "t", "", "Authentication token. Can either be the path to the token file, or the token itself")
	rootCmd.PersistentFlags().StringVarP(&appCfg.apiURL, "api-url", "", "", "Override the default API URL")
	rootCmd.PersistentFlags().BoolVarP(&appCfg.checkToken, "check-token", "", false, "Check if the token is valid and exit")
	rootCmd.PersistentFlags().StringVarP(&appCfg.controlAPI, "control", "", "", "Enable the control API on the "+apiListener)
	rootCmd.PersistentFlags().StringVarP(&appCfg.group, "group", "", "", "Group to grant access to the control API")
	rootCmd.PersistentFlags().BoolVarP(&appCfg.showVers, "version", "v", false, "Print the version and exit")
	rootCmd.PersistentFlags().StringVarP(&appCfg.logPath, "log", "l", "", "Log file path. Log to stderr if not specified")
	rootCmd.PersistentFlags().BoolVarP(&appCfg.debug, "debug", "d", false, "Enable debug logging")
	// Default from env var if present
	defaultProxyUseNames := false
	if v := strings.TrimSpace(os.Getenv("FARCASTER_PROXY_NAMES")); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			defaultProxyUseNames = b
		}
	}

	rootCmd.PersistentFlags().BoolVarP(&appCfg.ipv6, "ipv6", "", false, "Enable IPv6/AAAA DNS query resolution")
	rootCmd.PersistentFlags().BoolVar(&appCfg.proxyUseNames, "proxy-names", defaultProxyUseNames, "Use hostnames instead of IPs in proxy CONNECT/SOCKS5 requests")
	rootCmd.PersistentFlags().StringVar(&appCfg.dumpDir, "dump", "", "Write control, tunnel, and scan PCAP files to the provided directory")
	rootCmd.PersistentFlags().StringVarP(&appCfg.ifaceName, "interface", "i", "", "Network interface used for packet captures (required with --dump)")
}

// Execute runs the agent.
func Execute() {
	// Send all output to stderr.
	rootCmd.SetOut(os.Stderr)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// Main agent function.
func runAgent(cfg agentConfig) {
	logger, e := initLogger(cfg.debug, cfg.logPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, "Error:", e)
		os.Exit(1)
	}

	var (
		controlDump, tunnelDump, scanDump *netutils.PacketDumper
		controlCapture                    *netutils.ControlCapture
		captureCfg                        *agent.CaptureConfig
		ifaceAddr                         netip.Addr
	)

	cleanupDumpers := func() {
		closeDump := func(d **netutils.PacketDumper, name string) {
			if *d == nil {
				return
			}
			if err := (*d).Close(); err != nil {
				logger.Warnf("Failed to close %s dump %s: %v", name, (*d).Path(), err)
			}
			*d = nil
		}
		closeDump(&controlDump, "control")
		closeDump(&tunnelDump, "tunnel")
		closeDump(&scanDump, "scan")
	}

	exit := func(code int) {
		cleanupDumpers()
		_ = logger.Sync()
		os.Exit(code)
	}

	// Netstack's logger.
	// glog.SetLevel(glog.Debug)

	// If the --check-token flag is set, we just check if the token is valid.
	if cfg.checkToken {
		a := agent.New(cfg.token, cfg.apiURLs, logger, cfg.ipv6, cfg.proxyUseNames, nil)
		if err := a.CheckToken(); err != nil {
			logger.Errorf("Token validation failed: %v", err)
			exit(1)
		}
		logger.Info("Token successfully validated")
		exit(0)
	}

	// The agent can run as a service. Clients use the "Control API" to manage it.
	if cfg.controlAPI != "" {
		s, err := control.NewServer(cfg.controlAPI, cfg.group, logger)
		if err != nil {
			logger.Errorf("Could not start control API: %v", err)
			exit(1)
		}
		err = s.Run()
		if err != nil {
			logger.Errorf("Server failed: %v", err)
			exit(1)
		}
		exit(0)
	}

	if cfg.dumpDir != "" {
		if strings.TrimSpace(cfg.ifaceName) == "" {
			logger.Error("--interface is required when --dump is enabled")
			exit(1)
		}
		ifaceAddr, e = interfaceIPv4(cfg.ifaceName)
		if e != nil {
			logger.Errorf("Could not determine IPv4 address for interface %s: %v", cfg.ifaceName, e)
			exit(1)
		}

		timestamp := time.Now().Format("20060102-150405")
		controlPath := filepath.Join(cfg.dumpDir, fmt.Sprintf("farcaster-control-%s.pcap", timestamp))
		tunnelPath := filepath.Join(cfg.dumpDir, fmt.Sprintf("farcaster-tunnel-%s.pcap", timestamp))
		scanPath := filepath.Join(cfg.dumpDir, fmt.Sprintf("farcaster-scan-%s.pcap", timestamp))

		controlDump, e = netutils.NewPacketDumper(controlPath)
		if e != nil {
			logger.Errorf("Could not create control dump: %v", e)
			exit(1)
		}
		logger.Infof("Writing control traffic to %s", controlDump.Path())

		tunnelDump, e = netutils.NewPacketDumper(tunnelPath)
		if e != nil {
			logger.Errorf("Could not create tunnel dump: %v", e)
			exit(1)
		}
		logger.Infof("Writing tunnel traffic to %s", tunnelDump.Path())

		scanDump, e = netutils.NewPacketDumper(scanPath)
		if e != nil {
			logger.Errorf("Could not create scan dump: %v", e)
			exit(1)
		}
		logger.Infof("Writing scan traffic to %s", scanDump.Path())

		controlCapture = netutils.NewControlCapture(controlDump, controlHosts(cfg.apiURLs))
		captureCfg = &agent.CaptureConfig{
			InterfaceIP: ifaceAddr,
			Control:     controlCapture,
			TunnelDump:  tunnelDump,
			ScanDump:    scanDump,
		}
	}

	startAgent := func() error {
		a := agent.New(cfg.token, cfg.apiURLs, logger, cfg.ipv6, cfg.proxyUseNames, captureCfg)
		if err := a.ConnectWait(maxConnTries); err != nil {
			a.Close()
			return err
		}
		return nil
	}

	// Start the agent as a Windows service.
	if isWindowsService() {
		if err := runWindowsService(settings.Name, startAgent, logger); err != nil {
			logger.Errorf("Agent failed: %v", err)
			exit(1)
		}
		exit(0)
	}

	// Start the agent as a foreground process.
	if err := startAgent(); err != nil {
		logger.Errorf("Agent failed: %v", err)
		exit(1)
	}
	logger.Info("Agent successfully started")

	go watchMemoryUsage(logger)
	waitForTermination()

	logger.Info("Shutting down...")
	exit(0)
}

func waitForTermination() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received.
	<-c

	signal.Reset()
	close(c)
}

func watchMemoryUsage(log *zap.SugaredLogger) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()

	for range t.C {
		log.Info(system.GetMemStats())
	}
}

func getToken(token string) string {
	if token != "" {
		return token
	}
	envToken := os.Getenv(envTokenName)
	if envToken != "" {
		return envToken
	}
	return os.Getenv(envOldTokenName)
}

func getAPIURLs(apiURL string) []string {
	if apiURL != "" {
		return []string{apiURL}
	}
	envURL := os.Getenv(envAPIURLName)
	if envURL != "" {
		envURL = strings.Trim(envURL, "\"' ")
		return []string{envURL}
	}
	return defaultAPIURLs
}

func interfaceIPv4(name string) (netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP.To4(); ip != nil {
				if parsed, ok := netip.AddrFromSlice(ip); ok {
					return parsed, nil
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %s does not have an IPv4 address", name)
}

func controlHosts(urls []string) []string {
	seen := make(map[string]struct{})
	var hosts []string
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.TrimSpace(strings.ToLower(u.Hostname()))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}
