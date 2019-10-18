// +build !windows

package tcpioneer

import (
	//"bytes"
	//"encoding/binary"
	//"fmt"
	//"log"
	"net"
	//"time"
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

func getCookies(option []byte) []byte {
	optOff := 0
	for {
		if optOff >= len(option) {
			return nil
		}

		if option[optOff] == 1 {
			optOff++
		} else if option[optOff] == 34 {
			optLen := int(option[optOff+1])
			return option[optOff+2 : optOff+optLen]
		} else {
			optOff += int(option[optOff+1])
		}
	}

	return nil
}

func TCPDaemon(address string, forward bool) {
	wg.Add(1)
	defer wg.Done()
}

func NAT64(ipv6 net.IP, ipv4 net.IP, forward bool) {
	wg.Add(1)
	defer wg.Done()
}
