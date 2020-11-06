package tcpioneer

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/macronut/godivert"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func Scan(ipRange string) {
	mutex.Lock()
	winDivert, err := godivert.NewWinDivertHandle("false")
	mutex.Unlock()
	if err != nil {
		log.Println(err)
		return
	}
	DetectEnable = true

	var winDivertAddr godivert.WinDivertAddress

	var packet godivert.Packet
	packet.PacketLen = 40
	winDivertAddr.Data = 1 << 4
	packet.Addr = &winDivertAddr
	packet.Raw = []byte{
		0x45, 0, 0, 40,
		0, 0, 0x40, 0,
		byte(64), 6, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 1, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0x50, TCP_SYN, 0, 0,
		0, 0, 0, 0}

	srcIP := getMyIPv4()
	copy(packet.Raw[12:], srcIP)

	binary.BigEndian.PutUint16(packet.Raw[22:], uint16(443))

	fmt.Println("Start scanning", ipRange, "from", srcIP)

	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		log.Println(err)
		return
	}

	for iptmp := ip.Mask(ipNet.Mask); ipNet.Contains(iptmp); inc(iptmp) {
		ip4 := iptmp.To4()
		if ip4 != nil {
			copy(packet.Raw[16:], ip4)
			packet.CalcNewChecksum(winDivert)
			_, err := winDivert.Send(&packet)
			if err != nil {
				log.Println(err, packet)
			}
		}
		time.Sleep(time.Millisecond)
	}

	fmt.Println("End scan")
}

var checkMutex sync.Mutex

func CheckServer(URL string, ip net.IP) {
	//fmt.Println(ip, "found")
	u, err := url.Parse(URL)
	if err != nil {
		log.Println(err, URL)
		return
	}

	if u.Scheme != "https" {
		log.Println(URL, "is not https")
		return
	}

	d := net.Dialer{Timeout: time.Second * 2}
	conf := &tls.Config{
		ServerName: u.Host,
		//InsecureSkipVerify: true,
	}
	addr := net.TCPAddr{IP: ip, Port: 443}
	//checkMutex.Lock()
	//defer checkMutex.Unlock()
	conn, err := tls.DialWithDialer(&d, "tcp", addr.String(), conf)
	if err != nil {
		//log.Println(err, ip)
		return
	}
	defer conn.Close()

	request := fmt.Sprintf("HEAD %s HTTP/1.1\r\nHost: %s\r\n\r\n", u.Path, u.Host)
	_, err = conn.Write([]byte(request))
	if err != nil {
		//log.Println(err, ip)
		return
	}

	var reponse [2048]byte
	n, err := conn.Read(reponse[:])
	if err != nil {
		//log.Println(err, ip)
		return
	}

	if strings.HasPrefix(string(reponse[:n]), "HTTP/1.1 200 ") {
		fmt.Printf(ip.String() + ",")
	}
}
