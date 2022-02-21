package tcpioneer

import (
	"bufio"
	"encoding/xml"
	"log"
	"net"
	"os"
	"strings"
)

func ReadResultFile(s string) []net.IP {
	if strings.HasSuffix(s, ".xml") {
		return ReadXMLFile(s)
	} else {
		return ReadTextFile(s)
	}
}

func ReadTextFile(s string) []net.IP {
	file, err := os.Open(s)
	result := []net.IP{}
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		ip := net.ParseIP(scan.Text())
		if ip != nil {
			result = append(result, ip)
		}
	}
	return result
}

type MasscanAddress struct {
	Addr string `xml:"addr,attr"`
}

type MasscanHost struct {
	XMLName xml.Name       `xml:"host"`
	Address MasscanAddress `xml:"address"`
}

type MasscanResult struct {
	XMLName xml.Name      `xml:"nmaprun"`
	Hosts   []MasscanHost `xml:"host"`
}

func ReadXMLFile(s string) []net.IP {
	file, err := os.Open(s)
	result := []net.IP{}
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	decoder := xml.NewDecoder(file)
	xmlResult := MasscanResult{}
	err = decoder.Decode(&xmlResult)
	if err != nil {
		log.Fatal(err)
	}
	for _, host := range xmlResult.Hosts {
		ip := net.ParseIP(host.Address.Addr)
		if ip != nil {
			result = append(result, ip)
		}
	}
	return result
}
