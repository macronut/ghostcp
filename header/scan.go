package tcpioneer

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
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

func Scan(ipRange string, speed int) {
	mutex.Lock()
	winDivert, err := godivert.NewWinDivertHandle("false")
	mutex.Unlock()
	if err != nil {
		log.Println(err)
		return
	}

	var winDivertAddr godivert.WinDivertAddress

	var packet godivert.Packet
	winDivertAddr.Data = 1 << 4
	packet.Addr = &winDivertAddr
	packet.Raw = []byte{
		0x45, 0, 0, 0,
		0, 0, 0x40, 0,
		byte(64), 6, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0x80, TCP_SYN, 0xFA, 0xF0,
		0, 0, 0, 0,
		2, 4, 0x5, 0xB4,
		1, 3, 0x3, 0x8,
		1, 1, 4, 0x2}
	packet.PacketLen = uint(len(packet.Raw))
	binary.BigEndian.PutUint16(packet.Raw[2:], uint16(packet.PacketLen))

	srcIP := getMyIPv4()
	copy(packet.Raw[12:], srcIP)

	binary.BigEndian.PutUint16(packet.Raw[20:], uint16(2))
	binary.BigEndian.PutUint16(packet.Raw[22:], uint16(443))

	fmt.Println("Start scanning", ipRange, "from", srcIP)

	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		log.Println(err)
		return
	}

	timeTicker := time.NewTicker(time.Millisecond)
	defer timeTicker.Stop()
	i := 0
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
		i++
		if (i % speed) == 0 {
			<-timeTicker.C
		}
	}

	fmt.Println("End scan")
}

func CheckServer(URL string, ip net.IP, timeout uint) {
	u, err := url.Parse(URL)
	if err != nil {
		log.Println(err, URL)
		return
	}

	if u.Scheme != "https" {
		log.Println(URL, "is not https")
		return
	}

	c, ok := domainLookup(u.Host)
	if ok {
		IPMap[ip.String()] = IPConfig{c.Option, c.TTL, c.MAXTTL, c.MSS}
		time.Sleep(time.Millisecond)
	}

	var conn net.Conn
	addr := net.TCPAddr{IP: ip, Port: 443}
	conf := &tls.Config{
		ServerName: u.Host,
	}
	if timeout != 0 {
		d := net.Dialer{Timeout: time.Millisecond * time.Duration(timeout)}
		conn, err = tls.DialWithDialer(&d, "tcp", addr.String(), conf)
	} else {
		conn, err = tls.Dial("tcp", addr.String(), conf)
	}

	if err != nil {
		logPrintln(2, err, ip)
		return
	}
	defer conn.Close()

	if u.Path == "" {
		u.Path = "/"
	}

	request := fmt.Sprintf("HEAD %s HTTP/1.1\r\nHost: %s\r\n", u.Path, u.Host)
	request += "Accept: */*\r\n"
	request += "Accept-Encoding: gzip, deflate, br\r\n"
	request += "Accept-Language: en;q=0.9;q=0.8;q=0.7\r\n"
	//request += "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1\r\n"
	request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36\r\n"
	request += "\r\n"

	_, err = conn.Write([]byte(request))
	if err != nil {
		logPrintln(2, err, ip)
		return
	}

	var reponse [2048]byte
	n, err := conn.Read(reponse[:])
	if err != nil {
		logPrintln(2, err, ip)
		return
	}

	if strings.HasPrefix(string(reponse[:n]), "HTTP/1.1 200 ") {
		fmt.Printf(ip.String() + ",")
	} else {
		logPrintln(3, string(reponse[:n]))
	}
}
