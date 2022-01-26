package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Macronut/TCPioneer/header"
	"github.com/chai2010/winsvc"
)

var ServiceMode bool = true
var ScanIPRange string = ""
var ScanSpeed int = 1
var ScanURL string = ""
var ScanTimeout uint = 0

func StartService() {
	runtime.GOMAXPROCS(1)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if tcpioneer.LogLevel > 0 {
		var logFilename string = "tcpioneer.log"
		logFile, err := os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE, 0777)
		if err != nil {
			log.Println(err)
			return
		}
		defer logFile.Close()

		tcpioneer.Logger = log.New(logFile, "\r\n", log.Ldate|log.Ltime|log.Lshortfile)
	}

	err := tcpioneer.LoadConfig()
	if err != nil {
		if tcpioneer.LogLevel > 0 || !ServiceMode {
			log.Println(err)
		}
		return
	}

	Windir := os.Getenv("WINDIR")
	err = tcpioneer.LoadHosts(Windir + "\\System32\\drivers\\etc\\hosts")
	if err != nil && !ServiceMode {
		log.Println(err)
		return
	}

	if tcpioneer.LogLevel == 0 && !ServiceMode {
		tcpioneer.LogLevel = 1
	}

	if ScanIPRange != "" {
		tcpioneer.DetectEnable = true
		tcpioneer.ScanURL = ScanURL
		tcpioneer.ScanTimeout = ScanTimeout
	}

	tcpioneer.TCPDaemon(":443", false)
	tcpioneer.TCPDaemon(":80", false)
	tcpioneer.UDPDaemon(443, false)
	tcpioneer.TCPRecv(443, false)

	if tcpioneer.Forward {
		tcpioneer.TCPDaemon(":443", true)
		tcpioneer.TCPDaemon(":80", true)
		tcpioneer.UDPDaemon(443, true)
		tcpioneer.TCPRecv(443, true)
	}

	if tcpioneer.DNS == "" {
		tcpioneer.DNSRecvDaemon()
	} else {
		tcpioneer.TCPDaemon(tcpioneer.DNS, false)
		tcpioneer.DNSDaemon()
	}

	if ScanIPRange != "" {
		go tcpioneer.Scan(ScanIPRange, ScanSpeed)
	}

	fmt.Println("Service Start")
	tcpioneer.Wait()
}

func StopService() {
	arg := []string{"/flushdns"}
	cmd := exec.Command("ipconfig", arg...)
	d, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(d), err)
	}

	os.Exit(0)
}

func main() {
	serviceName := "TCPPioneer"
	var flagServiceInstall bool
	var flagServiceUninstall bool
	var flagServiceStart bool
	var flagServiceStop bool

	flag.BoolVar(&flagServiceInstall, "install", false, "Install service")
	flag.BoolVar(&flagServiceUninstall, "remove", false, "Remove service")
	flag.BoolVar(&flagServiceStart, "start", false, "Start service")
	flag.BoolVar(&flagServiceStop, "stop", false, "Stop service")
	flag.StringVar(&ScanIPRange, "scanip", "", "Scan IP Range")
	flag.IntVar(&ScanSpeed, "scanspeed", 1, "Scan Speed")
	flag.StringVar(&ScanURL, "scanurl", "", "Scan URL")
	flag.UintVar(&ScanTimeout, "scantimeout", 0, "Scan Timeout")
	flag.Parse()

	appPath, err := winsvc.GetAppPath()
	if err != nil {
		log.Fatal(err)
	}

	// install service
	if flagServiceInstall {
		if err := winsvc.InstallService(appPath, serviceName, ""); err != nil {
			log.Fatalf("installService(%s, %s): %v\n", serviceName, "", err)
		}
		log.Printf("Done\n")
		return
	}

	// remove service
	if flagServiceUninstall {
		if err := winsvc.RemoveService(serviceName); err != nil {
			log.Fatalln("removeService:", err)
		}
		log.Printf("Done\n")
		return
	}

	// start service
	if flagServiceStart {
		if err := winsvc.StartService(serviceName); err != nil {
			log.Fatalln("startService:", err)
		}
		log.Printf("Done\n")
		return
	}

	// stop service
	if flagServiceStop {
		if err := winsvc.StopService(serviceName); err != nil {
			log.Fatalln("stopService:", err)
		}
		log.Printf("Done\n")
		return
	}

	// run as service
	if !winsvc.IsAnInteractiveSession() {
		log.Println("main:", "runService")

		if err := os.Chdir(filepath.Dir(appPath)); err != nil {
			log.Fatal(err)
		}

		if err := winsvc.RunAsService(serviceName, StartService, StopService, false); err != nil {
			log.Fatalf("svc.Run: %v\n", err)
		}
		return
	}

	ServiceMode = false
	StartService()
}
