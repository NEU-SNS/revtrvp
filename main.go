package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/net/trace"

	"google.golang.org/grpc/grpclog"

	"github.com/NEU-SNS/revtrvp/config"
	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/plvp"
	"github.com/NEU-SNS/revtrvp/util"
)

var (
	defaultConfig = "./plvp.config"
	configPath    string
	versionNo     string
	vFlag         bool
	pidFile       string
	lockFile      string
)

func init() {
	configArg := os.Args[2]
	configPath = configArg
    log.Info(configArg)
	config.SetEnvPrefix("REVTR")
	if configPath == "" {
		config.AddConfigPath(defaultConfig)
	} else {
		config.AddConfigPath(configPath)
	}
	flag.BoolVar(plvp.Conf.Environment.Debug, "debug", false, "Environment used (debug, production)")
	flag.BoolVar(&vFlag, "version", false,
		"Prints the current version")
	flag.StringVar(plvp.Conf.Local.Addr, "a", ":65000",
		"The address to run the local service on")
	flag.StringVar(plvp.Conf.Local.Interface, "i", "net1", 
		"The network interface used by the plvp to connect to the plcontroller")
	flag.BoolVar(plvp.Conf.Local.CloseStdDesc, "d", false,
		"Close std file descripters")
	flag.BoolVar(plvp.Conf.Local.AutoConnect, "auto-connect", false,
		"Autoconnect to 0.0.0.0 and will use port 55000")
	flag.StringVar(plvp.Conf.Local.PProfAddr, "pprof-addr", ":55557",
		"The address to use for pperf")
	flag.StringVar(plvp.Conf.Local.Host, "host", "plcontroller.revtr.ccs.neu.edu",
		"The url for the plcontroller service")
	flag.IntVar(plvp.Conf.Local.Port, "p", 4380,
		"The port the controller service is listening on")
	flag.BoolVar(plvp.Conf.Local.StartScamp, "start-scamper", true,
		"Determines if scamper starts or not.")
	flag.StringVar(plvp.Conf.Scamper.BinPath, "b", "/usr/local/bin/scamper",
		"The path to the scamper binary")
	flag.StringVar(plvp.Conf.Scamper.Port, "scamper-port", "4381",
		"The port scamper will try to connect to.")
	flag.StringVar(plvp.Conf.Scamper.Host, "scamper-host", "plcontroller.revtr.ccs.neu.edu",
		"The host that the sc_remoted process is running, should most likely match the host arg")
	flag.StringVar(plvp.Conf.Scamper.Rate, "scamper-rate", "100",
	"The probing rate of the source")
	grpclog.SetLogger(log.GetLogger())
	trace.AuthRequest = func(req *http.Request) (any, sensitive bool) {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		switch {
		case err != nil:
			return false, false
		case host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "syrah.ccs.neu.edu" || host == "129.10.110.48":
			return true, true
		default:
			return false, false
		}
	}
}

func main() {

	go sigHandle()
	err := config.Parse(flag.CommandLine, &plvp.Conf)
	if err != nil {
		log.Errorf("Failed to parse config: %v", err)
		exit(1)
	}
	if vFlag {
		fmt.Println(versionNo)
		exit(0)
	}
	//	_, err = os.Stat(lockFile)
	//	if err == nil {
	//		log.Debug("Lockfile exists")
	//		exit(1)
	//	} else {
	//		_, err = os.Create(lockFile)
	//		if err != nil {
	//			log.Error(err)
	//			exit(1)
	//		}
	//	}
	rootArg := os.Args[1]
    log.Info(rootArg)
	util.CloseStdFiles(*plvp.Conf.Local.CloseStdDesc)
	err = <-plvp.Start(plvp.Conf, &plvp.PLControllerSender{RootCA: rootArg})
	if err != nil {
		log.Errorf("PLVP Start returned with error: %v", err)
		exit(1)
	}


	
}

func exit(status int) {
	os.Remove(pidFile)
	os.Exit(status)
}

func sigHandle() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGQUIT, syscall.SIGSTOP)
	for sig := range c {
		log.Infof("Got signal: %v", sig)
		os.Remove(lockFile)
		plvp.HandleSig(sig)
		exit(1)
	}
}
