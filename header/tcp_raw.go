// +build !windows

package tcpioneer

import (
	//"bytes"
	//"encoding/binary"
	//"fmt"
	"log"
	"net"

	//"time"
	"syscall"
)

type ConnInfo struct {
	Option uint32
	SeqNum uint32
	AckNum uint32
	TTL    byte
	MAXTTL byte
}

var PortList4 [65536]*ConnInfo
var PortList6 [65536]*ConnInfo
var OptionMap map[string][]byte
var SynOption4 []byte
var SynOption6 []byte

const (
	TCP_FIN = byte(0x01)
	TCP_SYN = byte(0x02)
	TCP_RST = byte(0x04)
	TCP_PSH = byte(0x08)
	TCP_ACK = byte(0x10)
	TCP_URG = byte(0x20)
	TCP_ECE = byte(0x40)
	TCP_CWR = byte(0x80)
)

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	LocalAddr := conn.LocalAddr()
	LocalTCPAddr, err := net.ResolveTCPAddr(LocalAddr.Network(), LocalAddr.String())

	if LocalTCPAddr.IP.To4() == nil {
		mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(file.Fd()), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		raw := mtuinfo.Addr
		var ip net.IP = raw.Addr[:]

		port := int(raw.Port&0xFF)<<8 | int(raw.Port&0xFF00)>>8
		TCPAddr := net.TCPAddr{ip, port, ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	} else {
		raw, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		var ip net.IP = raw.Multiaddr[4:8]
		port := int(raw.Multiaddr[2])<<8 | int(raw.Multiaddr[3])
		TCPAddr := net.TCPAddr{ip, port, ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	}

	return nil, nil
}

func TCPDaemon(address string, forward bool) {
	wg.Add(1)
	defer wg.Done()

	laddr := &net.TCPAddr{net.ParseIP("0.0.0.0"), 8, ""}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err)
		}
		return
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if LogLevel > 0 {
				log.Println(err)
			}
			continue
		}

		go func(conn *net.TCPConn) {
			GetOriginalDST(conn)
		}(conn)
	}
}

func NAT64(ipv6 net.IP, ipv4 net.IP, forward bool) {
	wg.Add(1)
	defer wg.Done()
}
