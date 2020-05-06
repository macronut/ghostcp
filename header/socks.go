package tcpioneer

import (
	"encoding/binary"
	"io"
	"log"
	"net"
)

func SocksProxyAddr(conn net.Conn, ip net.IP, port int, proxy *net.TCPAddr, header []byte) {
	remote, err := net.DialTCP("tcp", nil, proxy)
	if err != nil {
		log.Println(err)
		return
	}
	defer remote.Close()

	{
		var b [25]byte
		_, err = remote.Write([]byte{0x05, 0x01, 0x00})
		if err != nil {
			log.Println(err)
			return
		}
		_, err = remote.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}
		if b[0] != 0x05 {
			log.Println("VER:", b[0])
			return
		}
		headLen := 4
		ip4 := ip.To4()
		if ip4 != nil {
			copy(b[:], []byte{0x05, 0x01, 0x00, 0x01})
			copy(b[4:], ip4[:4])
			headLen += 4
		} else {
			copy(b[:], []byte{0x05, 0x01, 0x00, 0x04})
			copy(b[4:], ip[:16])
			headLen += 16
		}
		binary.BigEndian.PutUint16(b[headLen:], uint16(port))
		headLen += 2
		_, err = remote.Write(b[:headLen])
		if err != nil {
			log.Println(err)
			return
		}
		n, err := remote.Read(b[:])
		if err != nil {
			log.Println(ip, port, err)
			return
		}
		if n < 2 {
			return
		}
		if b[0] != 0x05 {
			log.Println("VER:", b[0])
			return
		}
		if b[1] != 0x00 {
			log.Println("REP:", b[1])
			return
		}
		if header != nil {
			_, err := remote.Write(header)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}

	go io.Copy(remote, conn)
	io.Copy(conn, remote)
}

func SocksProxyHost(conn net.Conn, host string, port int, proxy *net.TCPAddr, header []byte) {
	remote, err := net.DialTCP("tcp", nil, proxy)
	if err != nil {
		log.Println(err)
		return
	}
	defer remote.Close()

	{
		var b [512]byte
		_, err = remote.Write([]byte{0x05, 0x01, 0x00})
		if err != nil {
			log.Println(err)
			return
		}
		_, err = remote.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}
		if b[0] != 0x05 {
			log.Println("VER:", b[0])
			return
		}
		copy(b[:], []byte{0x05, 0x01, 0x00, 0x03})
		bHost := []byte(host)
		hostLen := len(bHost)
		b[4] = byte(hostLen)
		copy(b[5:], bHost)
		binary.BigEndian.PutUint16(b[5+hostLen:], uint16(port))
		_, err = remote.Write(b[:7+hostLen])
		if err != nil {
			log.Println(err)
			return
		}
		n, err := remote.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}
		if n < 2 {
			return
		}
		if b[0] != 0x05 {
			log.Println("VER:", b[0])
			return
		}
		if b[1] != 0x00 {
			log.Println("REP:", b[1])
			return
		}
		if header != nil {
			_, err := remote.Write(header)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}

	go io.Copy(remote, conn)
	io.Copy(conn, remote)
}
