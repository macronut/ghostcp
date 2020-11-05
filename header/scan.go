package tcpioneer

import (
	"encoding/binary"
	"log"
	"net"
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

func Scan(ipRange string) error {
	mutex.Lock()
	winDivert, err := godivert.NewWinDivertHandle("false")
	mutex.Unlock()
	if err != nil {
		return err
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

	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return err
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

	return nil
}
