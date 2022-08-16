package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/chai2010/winsvc"
	"github.com/macronut/ghostcp/header"
)

var ServiceMode bool = true
var ScanIPRange string = ""
var ScanSpeed int = 1
var ScanURL string = ""
var ScanTimeout uint = 0

func StartService() {
	runtime.GOMAXPROCS(1)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if ghostcp.LogLevel > 0 {
		var logFilename string = "ghostcp.log"
		logFile, err := os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE, 0777)
		if err != nil {
			log.Println(err)
			return
		}
		defer logFile.Close()

		ghostcp.Logger = log.New(logFile, "\r\n", log.Ldate|log.Ltime|log.Lshortfile)
	}

	err := ghostcp.LoadConfig()
	if err != nil {
		if ghostcp.LogLevel > 0 || !ServiceMode {
			log.Println(err)
		}
		return
	}

	Windir := os.Getenv("WINDIR")
	err = ghostcp.LoadHosts(Windir + "\\System32\\drivers\\etc\\hosts")
	if err != nil && !ServiceMode {
		log.Println(err)
		return
	}

	if ghostcp.LogLevel == 0 && !ServiceMode {
		ghostcp.LogLevel = 1
	}

	if ScanIPRange != "" {
		ghostcp.DetectEnable = true
		ghostcp.ScanURL = ScanURL
		ghostcp.ScanTimeout = ScanTimeout
	}

	ghostcp.TCPDaemon(":443", false)
	ghostcp.TCPDaemon(":80", false)
	ghostcp.UDPDaemon(443, false)
	ghostcp.TCPRecv(":443", false)

	if ghostcp.Forward {
		ghostcp.TCPDaemon(":443", true)
		ghostcp.TCPDaemon(":80", true)
		ghostcp.UDPDaemon(443, true)
		ghostcp.TCPRecv(":443", true)
	}

	if ghostcp.DNS == "" {
		ghostcp.DNSRecvDaemon()
	} else {
		ghostcp.TCPDaemon(ghostcp.DNS, false)
		ghostcp.TCPRecv(ghostcp.DNS, false)
		ghostcp.DNSDaemon()
	}

	if ScanIPRange != "" {
		go ghostcp.Scan(ScanIPRange, ScanSpeed)
	}

	fmt.Println("Service Start")
	ghostcp.Wait()
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
	serviceName := "GhosTCP"
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
