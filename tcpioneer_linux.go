package main

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"./header"
)

var ServiceMode bool = false

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

	go tcpioneer.TCPDaemon("", true)
	if tcpioneer.Forward {
	}

	go tcpioneer.DNSDaemon()

	fmt.Println("Service Start")
	tcpioneer.Wait()
}

func start() {
	StartService()
}
