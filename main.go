package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/williamfhe/godivert"
)

var mutex sync.RWMutex

var DomainMap map[string]int
var IPMap map[string]int
var DNS string
var TTL int
var MSS int

func tcp_lookup(request []byte, address string) ([]byte, error) {
	server, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer server.Close()
	data := make([]byte, 4096)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	_, err = server.Write(data[:len(request)+2])
	if err != nil {
		return nil, err
	}

	length := 0
	recvlen := 0
	for {
		n, err := server.Read(data[length:])
		if err != nil {
			return nil, err
		}
		if length == 0 {
			length = int(binary.BigEndian.Uint16(data[:2]) + 2)
		}
		recvlen += n
		if recvlen >= length {
			return data[2:recvlen], nil
		}
	}

	return nil, nil
}

func get_qname(buf []byte) (string, int) {
	bufflen := len(buf)
	if bufflen < 13 {
		return "", 0
	}
	length := buf[12]
	off := 13
	end := off + int(length)
	qname := string(buf[off:end])
	off = end

	for {
		if off > bufflen {
			return "", 0
		}
		length := buf[off]
		off++
		if length == 0x00 {
			break
		}
		end := off + int(length)
		qname += "." + string(buf[off:end])
		off = end
	}

	return qname, off + 4
}

func domainLookup(qname string) int {
	level, ok := DomainMap[qname]
	if ok {
		return level
	}

	offset := 0
	for i := 0; i < 2; i++ {
		off := strings.Index(qname[offset:], ".")
		if off == -1 {
			return 0
		}
		offset += off
		level, ok = DomainMap[qname[offset:]]
		if ok {
			return level
		}
		offset++
	}

	return 0
}

func getAnswers(answers []byte, count int) []string {
	ips := make([]string, 0)
	offset := 0
	for i := 0; i < count; i++ {
		for {
			length := binary.BigEndian.Uint16(answers[offset : offset+2])
			offset += 2
			if length > 0 && length < 63 {
				offset += int(length)
				if offset > len(answers)-2 {
					return nil
				}
			} else {
				break
			}
		}
		AType := binary.BigEndian.Uint16(answers[offset : offset+2])
		offset += 8
		DataLength := binary.BigEndian.Uint16(answers[offset : offset+2])
		offset += 2

		if AType == 1 {
			data := answers[offset : offset+4]
			ip := net.IPv4(data[0], data[1], data[2], data[3]).String()
			ips = append(ips, ip)
		} else if AType == 28 {
			var data [16]byte
			copy(data[:], answers[offset:offset+16])
			ip := net.IP(answers[offset : offset+16]).String()
			ips = append(ips, ip)
		}
		offset += int(DataLength)
	}

	return ips
}

func dns_daemon() {
	arg := []string{"/flushdns"}
	cmd := exec.Command("ipconfig", arg...)
	d, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(d), err)
		return
	}

	filter := "udp.DstPort == 53"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Println(err)
			continue
		}

		ipheadlen := int(packet.Raw[0]&0xF) * 4
		udpheadlen := 8
		qname, off := get_qname(packet.Raw[ipheadlen+udpheadlen:])

		level := domainLookup(qname)
		if level > 0 {
			log.Println(qname)

			response, err := tcp_lookup(packet.Raw[ipheadlen+udpheadlen:], DNS)
			if err != nil {
				log.Println(err)
				continue
			}

			count := int(binary.BigEndian.Uint16(response[6:8]))
			ips := getAnswers(response[off:], count)
			mutex.Lock()
			for _, ip := range ips {
				IPMap[ip] = level
			}
			mutex.Unlock()

			copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
			packetsize := 28 + len(response)
			binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
			copy(rawbuf[12:], packet.Raw[16:20])
			copy(rawbuf[16:], packet.Raw[12:16])
			copy(rawbuf[20:], packet.Raw[22:24])
			copy(rawbuf[22:], packet.Raw[20:22])
			binary.BigEndian.PutUint16(rawbuf[24:], uint16(len(response)+8))
			copy(rawbuf[28:], response)
			packet.PacketLen = uint(packetsize)
			packet.Raw = rawbuf[:packetsize]

			packet.CalcNewChecksum(winDivert)
		}

		_, err = winDivert.Send(packet)
	}
}

func dot_daemon() {
	filter := "tcp.Psh and tcp.DstPort == 53"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Println(err)
			return
		}

		ipheadlen := int(packet.Raw[0]&0xF) * 4
		tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
		copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])
		rawbuf[8] = byte(10)
		fake_packet := *packet
		fake_packet.Raw = rawbuf[:len(packet.Raw)]
		fake_packet.CalcNewChecksum(winDivert)

		_, err = winDivert.Send(&fake_packet)
		if err != nil {
			log.Println(err)
			return
		}

		_, err = winDivert.Send(&fake_packet)
		if err != nil {
			log.Println(err)
			return
		}

		_, err = winDivert.Send(packet)
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func hello(SrcPort int, TTL int) error {
	filter := "tcp.Psh and tcp.SrcPort == " + strconv.Itoa(SrcPort)
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return err
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)

	packet, err := winDivert.Recv()
	if err != nil {
		log.Println(err)
		return err
	}

	ipheadlen := int(packet.Raw[0]&0xF) * 4
	tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
	copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])
	rawbuf[8] = byte(TTL)
	fake_packet := *packet
	fake_packet.Raw = rawbuf[:len(packet.Raw)]
	fake_packet.CalcNewChecksum(winDivert)

	_, err = winDivert.Send(&fake_packet)
	if err != nil {
		log.Println(err)
		return err
	}

	_, err = winDivert.Send(&fake_packet)
	if err != nil {
		log.Println(err)
		return err
	}

	_, err = winDivert.Send(packet)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func load_config() error {
	DomainMap = make(map[string]int)
	conf, err := os.Open("config")
	if err != nil {
		return err
	}
	defer conf.Close()

	br := bufio.NewReader(conf)
	level := 0
	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if len(line) > 0 {
			if line[0] == '#' {
				if string(line) == "#LEVEL1" {
					level = 1
				} else if string(line) == "#LEVEL2" {
					level = 2
				} else if string(line) == "#LEVEL3" {
					level = 3
				} else if string(line) == "#LEVEL4" {
					level = 4
				}
			} else {
				keys := strings.SplitN(string(line), "=", 2)
				if len(keys) > 1 {
					if keys[0] == "server" {
						DNS = keys[1]
						log.Println(string(line))
					} else if keys[0] == "ttl" {
						TTL, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						log.Println(string(line))
					} else if keys[0] == "mss" {
						MSS, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						log.Println(string(line))
					}

				} else {
					DomainMap[keys[0]] = level
				}
			}
		}
	}

	return nil
}

func main() {
	err := load_config()
	if err != nil {
		log.Println(err)
		return
	}
	IPMap = make(map[string]int)

	filter := "tcp.Syn and tcp.DstPort == 443"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return
	}
	defer winDivert.Close()

	go dns_daemon()
	go dot_daemon()

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Println(err)
			return
		}

		mutex.RLock()
		level, ok := IPMap[packet.DstIP().String()]
		mutex.RUnlock()

		if ok {
			ipheadlen := int(packet.Raw[0]&0xF) * 4

			if level > 3 {
				if len(packet.Raw) < ipheadlen+24 {
					log.Println(packet)
					return
				}

				option := packet.Raw[ipheadlen+20]
				if option == 2 {
					binary.BigEndian.PutUint16(packet.Raw[ipheadlen+22:], uint16(MSS))
					packet.CalcNewChecksum(winDivert)
				}
			}

			if level > 1 {
				SrcPort := int(binary.BigEndian.Uint16(packet.Raw[ipheadlen:]))
				go hello(SrcPort, TTL)
				log.Println(packet.DstIP(), "LEVEL", level)
			}
		}

		_, err = winDivert.Send(packet)
		if err != nil {

			log.Println(err)
			return
		}
	}
}
