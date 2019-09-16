package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/williamfhe/godivert"
)

type Config struct {
	Level   uint16
	ANCount uint16
	Answers []byte
}

var DomainMap map[string]Config
var IPMap map[string]int
var DNS string
var TTL int
var MSS int
var LocalDNS bool = false

func TCPlookup(request []byte, address string) ([]byte, error) {
	server, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer server.Close()
	data := make([]byte, 4096)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	_, err = server.Write(data[:20])
	if err != nil {
		return nil, err
	}

	_, err = server.Write(data[20 : len(request)+2])
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

func getQName(buf []byte) (string, int) {
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

func domainLookup(qname string) Config {
	config, ok := DomainMap[qname]
	if ok {
		return config
	}

	offset := 0
	for i := 0; i < 2; i++ {
		off := strings.Index(qname[offset:], ".")
		if off == -1 {
			return Config{0, 0, nil}
		}
		offset += off
		config, ok = DomainMap[qname[offset:]]
		if ok {
			return config
		}
		offset++
	}

	return Config{0, 0, nil}
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

func packAnswers(ips []string) []byte {
	count := len(ips)
	answers := make([]byte, 16*count)
	length := 0
	for _, ip := range ips {
		ip4 := net.ParseIP(ip).To4()
		if ip4 != nil {
			answer := []byte{0xC0, 0x0C, 0x00, 0x01,
				0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04,
				ip4[0], ip4[1], ip4[2], ip4[3]}
			copy(answers[length:], answer)
			length += 16
		}
	}

	return answers
}

func DNSDaemon() {
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

		ipv6 := packet.Raw[0]>>4 == 6
		if ipv6 {
			continue
		}

		ipheadlen := int(packet.Raw[0]&0xF) * 4
		udpheadlen := 8
		qname, off := getQName(packet.Raw[ipheadlen+udpheadlen:])

		config := domainLookup(qname)
		if config.Level > 0 {
			if config.ANCount > 0 {
				log.Println(qname)
				request := packet.Raw[ipheadlen+udpheadlen:]
				copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
				udpsize := len(request) + len(config.Answers) + 8
				packetsize := 20 + udpsize
				binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
				copy(rawbuf[12:], packet.Raw[16:20])
				copy(rawbuf[16:], packet.Raw[12:16])
				copy(rawbuf[20:], packet.Raw[22:24])
				copy(rawbuf[22:], packet.Raw[20:22])
				binary.BigEndian.PutUint16(rawbuf[24:], uint16(udpsize))
				copy(rawbuf[28:], request)
				rawbuf[30] = 0x81
				rawbuf[31] = 0x80
				binary.BigEndian.PutUint16(rawbuf[34:], config.ANCount)
				copy(rawbuf[28+len(request):], config.Answers)

				packet.PacketLen = uint(packetsize)
				packet.Raw = rawbuf[:packetsize]
				packet.CalcNewChecksum(winDivert)
			} else if !LocalDNS {
				log.Println(qname, config.Level)
				response, err := TCPlookup(packet.Raw[ipheadlen+udpheadlen:], DNS)
				if err != nil {
					log.Println(err)
					continue
				}

				count := int(binary.BigEndian.Uint16(response[6:8]))
				ips := getAnswers(response[off:], count)
				for _, ip := range ips {
					IPMap[ip] = int(config.Level)
				}

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
		}

		_, err = winDivert.Send(packet)
	}
}

func DNSRecvDaemon() {
	filter := "udp.SrcPort == 53"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return
	}
	defer winDivert.Close()

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Println(err)
			return
		}

		ipheadlen := int(packet.Raw[0]&0xF) * 4
		udpheadlen := 8
		qname, off := getQName(packet.Raw[ipheadlen+udpheadlen:])
		config := domainLookup(qname)

		if config.Level > 1 {
			log.Println(qname, config.Level)
			response := packet.Raw[ipheadlen+udpheadlen:]
			count := int(binary.BigEndian.Uint16(response[6:8]))
			ips := getAnswers(response[off:], count)
			for _, ip := range ips {
				IPMap[ip] = int(config.Level)
			}
		}
		_, err = winDivert.Send(packet)
	}
}

func DOTDaemon() {
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
		rawbuf[8] = byte(TTL)
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

func HTTPDaemon() {
	filter := "tcp.Psh and tcp.DstPort == 80"
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

		level, ok := IPMap[packet.DstIP().String()]

		if ok {
			if level > 1 {
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
					return
				}

				_, err = winDivert.Send(&fake_packet)
				if err != nil {
					log.Println(err)
					return
				}
			}
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

	time.Sleep(time.Microsecond * 10)

	_, err = winDivert.Send(packet)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func loadConfig() error {
	DomainMap = make(map[string]Config)
	IPMap = make(map[string]int)
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
				if string(line) == "#LEVEL0" {
					level = 0
				} else if string(line) == "#LEVEL1" {
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
						LocalDNS = DNS == "127.0.0.1:53"
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
					} else {
						ips := strings.Split(keys[1], ",")
						for _, ip := range ips {
							IPMap[ip] = level
						}
						DomainMap[keys[0]] = Config{uint16(level), uint16(len(ips)), packAnswers(ips)}
					}
				} else {
					DomainMap[keys[0]] = Config{uint16(level), 0, nil}
				}
			}
		}
	}

	return nil
}

func main() {
	runtime.GOMAXPROCS(1)

	err := loadConfig()
	if err != nil {
		log.Println(err)
		return
	}

	filter := "tcp.Syn and tcp.DstPort == 443"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return
	}
	defer winDivert.Close()

	go DNSDaemon()
	if LocalDNS {
		go DNSRecvDaemon()
	} else {
		go DOTDaemon()
	}

	go HTTPDaemon()

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Println(err)
			return
		}

		level, ok := IPMap[packet.DstIP().String()]

		if ok {
			ipheadlen := int(packet.Raw[0]&0xF) * 4

			if level > 2 {
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
