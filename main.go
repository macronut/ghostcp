package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/chai2010/winsvc"
	"github.com/williamfhe/godivert"
)

type Config struct {
	Option   uint32
	TTL      byte
	MAXTTL   byte
	MSS      uint16
	ANCount4 uint16
	ANCount6 uint16
	Answers4 []byte
	Answers6 []byte
}

type IPConfig struct {
	Option uint32
	TTL    byte
	MAXTTL byte
	MSS    uint16
}

type ConnInfo struct {
	Option uint32
	SeqNum uint32
	AckNum uint32
	TTL    byte
	MAXTTL byte
}

var DomainMap map[string]Config
var IPMap map[string]IPConfig
var PortList4 [65536]*ConnInfo
var PortList6 [65536]*ConnInfo
var OptionMap map[string][]byte
var SynOption4 []byte
var SynOption6 []byte
var DNS string = ""
var DNS64 string = ""
var LocalDNS bool = false
var ServiceMode bool = true
var IPv6Enable = false
var LogLevel = 0

const (
	OPT_TTL  = 0x01
	OPT_MSS  = 0x02
	OPT_MD5  = 0x04
	OPT_ACK  = 0x08
	OPT_SYN  = 0x10
	OPT_CSUM = 0x20
	OPT_TFO  = 0x40
)

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

var Logger *log.Logger

func logPrintln(v ...interface{}) {
	if LogLevel > 1 {
		log.Println(v)
	}
}

func TCPlookup(request []byte, address string) ([]byte, error) {
	server, err := net.DialTimeout("tcp", address, time.Second*5)
	if err != nil {
		return nil, err
	}
	defer server.Close()
	data := make([]byte, 1024)
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

func TCPlookupDNS64(request []byte, address string, offset int, prefix []byte) ([]byte, error) {
	response6 := make([]byte, 1024)
	offset6 := offset
	offset4 := offset

	binary.BigEndian.PutUint16(request[offset-4:offset-2], 1)
	response, err := TCPlookup(request, address)
	if err != nil {
		return nil, err
	}

	copy(response6, response[:offset])
	binary.BigEndian.PutUint16(response6[offset-4:offset-2], 28)

	count := int(binary.BigEndian.Uint16(response[6:8]))
	for i := 0; i < count; i++ {
		for {
			if offset >= len(response) {
				log.Println(offset)
				return nil, nil
			}
			length := response[offset]
			offset++
			if length == 0 {
				break
			}
			if length < 63 {
				offset += int(length)
				if offset+2 > len(response) {
					log.Println(offset)
					return nil, nil
				}
			} else {
				offset++
				break
			}
		}
		if offset+2 > len(response) {
			log.Println(offset)
			return nil, nil
		}

		copy(response6[offset6:], response[offset4:offset])
		offset6 += offset - offset4
		offset4 = offset

		AType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		if offset+2 > len(response) {
			log.Println(offset)
			return nil, nil
		}
		DataLength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		offset += int(DataLength)
		if AType == 1 {
			if offset > len(response) {
				log.Println(offset)
				return nil, nil
			}
			binary.BigEndian.PutUint16(response6[offset6:], 28)
			offset6 += 2
			offset4 += 2
			copy(response6[offset6:], response[offset4:offset4+6])
			offset6 += 6
			offset4 += 6
			binary.BigEndian.PutUint16(response6[offset6:], DataLength+12)
			offset6 += 2
			offset4 += 2

			copy(response6[offset6:], prefix[:12])
			offset6 += 12
			copy(response6[offset6:], response[offset4:offset])
			offset6 += offset - offset4
			offset4 = offset
		} else {
			copy(response6[offset6:], response[offset4:offset])
			offset6 += offset - offset4
			offset4 = offset
		}
	}

	return response6[:offset6], nil
}

func getQName(buf []byte) (string, int, int) {
	bufflen := len(buf)
	if bufflen < 13 {
		return "", 0, 0
	}
	length := buf[12]
	off := 13
	end := off + int(length)
	qname := string(buf[off:end])
	off = end

	for {
		if off >= bufflen {
			return "", 0, 0
		}
		length := buf[off]
		off++
		if length == 0x00 {
			break
		}
		end := off + int(length)
		if end > bufflen {
			return "", 0, 0
		}
		qname += "." + string(buf[off:end])
		off = end
	}
	end = off + 4
	if end > bufflen {
		return "", 0, 0
	}

	qtype := int(binary.BigEndian.Uint16(buf[off : off+2]))

	return qname, qtype, end
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
			return Config{0, 0, 0, 0, 0, 0, nil, nil}
		}
		offset += off
		config, ok = DomainMap[qname[offset:]]
		if ok {
			return config
		}
		offset++
	}

	return Config{0, 0, 0, 0, 0, 0, nil, nil}
}

func getAnswers(answers []byte, count int) []string {
	ips := make([]string, 0)
	offset := 0

	for i := 0; i < count; i++ {
		for {
			if offset >= len(answers) {
				return nil
			}
			length := answers[offset]
			offset++
			if length == 0 {
				break
			}
			if length < 63 {
				offset += int(length)
				if offset+2 > len(answers) {
					return nil
				}
			} else {
				offset++
				break
			}
		}
		if offset+2 > len(answers) {
			return nil
		}
		AType := binary.BigEndian.Uint16(answers[offset : offset+2])
		offset += 8
		if offset+2 > len(answers) {
			return nil
		}
		DataLength := binary.BigEndian.Uint16(answers[offset : offset+2])
		offset += 2

		if AType == 1 {
			if offset+4 > len(answers) {
				return nil
			}
			data := answers[offset : offset+4]
			ip := net.IPv4(data[0], data[1], data[2], data[3]).String()
			ips = append(ips, ip)
		} else if AType == 28 {
			var data [16]byte
			if offset+16 > len(answers) {
				return nil
			}
			copy(data[:], answers[offset:offset+16])
			ip := net.IP(answers[offset : offset+16]).String()
			ips = append(ips, ip)
		}

		offset += int(DataLength)
	}

	return ips
}

func packAnswers(ips []string, qtype int) (int, []byte) {
	totalLen := 0
	count := 0
	for _, ip := range ips {
		ip4 := net.ParseIP(ip).To4()
		if ip4 != nil && qtype == 1 {
			count++
			totalLen += 16
		} else if qtype == 28 {
			count++
			totalLen += 28
		}
	}

	answers := make([]byte, totalLen)
	length := 0
	for _, strIP := range ips {
		ip := net.ParseIP(strIP)
		ip4 := ip.To4()
		if ip4 != nil {
			if qtype == 1 {
				answer := []byte{0xC0, 0x0C, 0x00, 1,
					0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04,
					ip4[0], ip4[1], ip4[2], ip4[3]}
				copy(answers[length:], answer)
				length += 16
			}
		} else {
			if qtype == 28 {
				answer := []byte{0xC0, 0x0C, 0x00, 28,
					0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x10}
				copy(answers[length:], answer)
				length += 12
				copy(answers[length:], ip)
				length += 16
			}
		}
	}

	return count, answers
}

func DNSDaemon() {
	arg := []string{"/flushdns"}
	cmd := exec.Command("ipconfig", arg...)
	d, err := cmd.CombinedOutput()
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(string(d), err)
		}
		return
	}

	filter := "outbound and udp.DstPort == 53"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			if LogLevel > 0 || !ServiceMode {
				log.Println(err)
			}
			continue
		}

		ipv6 := packet.Raw[0]>>4 == 6

		var ipheadlen int
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(packet.Raw[0]&0xF) * 4
		}
		udpheadlen := 8
		qname, qtype, off := getQName(packet.Raw[ipheadlen+udpheadlen:])
		if qname == "" {
			logPrintln("DNS Segmentation fault")
			continue
		}

		config := domainLookup(qname)
		if config.Option > 0 || config.Answers4 != nil || config.Answers6 == nil {
			var anCount uint16 = 0
			var answers []byte = nil

			var noRecord bool
			if !IPv6Enable && qtype == 28 {
				noRecord = true
			} else {
				if qtype == 1 {
					if config.ANCount6 > 0 && config.ANCount4 == 0 {
						noRecord = true
					} else {
						answers = config.Answers4
						anCount = config.ANCount4
					}
				} else if qtype == 28 {
					if config.ANCount4 > 0 && config.ANCount6 == 0 {
						noRecord = true
					} else {
						answers = config.Answers6
						anCount = config.ANCount6
					}
				}
			}

			if noRecord {
				request := packet.Raw[ipheadlen+udpheadlen:]
				udpsize := len(request) + 8

				var packetsize int
				if ipv6 {
					copy(rawbuf, []byte{96, 12, 19, 68, 0, 98, 17, 128})
					packetsize = 40 + udpsize
					binary.BigEndian.PutUint16(rawbuf[4:], uint16(udpsize))
					copy(rawbuf[8:], packet.Raw[24:40])
					copy(rawbuf[24:], packet.Raw[8:24])
				} else {
					copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
					packetsize = 20 + udpsize
					binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
					copy(rawbuf[12:], packet.Raw[16:20])
					copy(rawbuf[16:], packet.Raw[12:16])
					ipheadlen = 20
				}

				copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
				copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
				binary.BigEndian.PutUint16(rawbuf[ipheadlen+4:], uint16(udpsize))
				copy(rawbuf[ipheadlen+8:], request)
				rawbuf[ipheadlen+10] = 0x81
				rawbuf[ipheadlen+11] = 0x80
				binary.BigEndian.PutUint16(rawbuf[ipheadlen+14:], 0)

				packet.PacketLen = uint(packetsize)
				packet.Raw = rawbuf[:packetsize]
				packet.CalcNewChecksum(winDivert)

				_, err = winDivert.Send(packet)
			} else {
				if anCount > 0 {
					logPrintln(qname)
					request := packet.Raw[ipheadlen+udpheadlen:]
					udpsize := len(request) + len(answers) + 8

					var packetsize int
					if ipv6 {
						copy(rawbuf, []byte{96, 12, 19, 68, 0, 98, 17, 128})
						packetsize = 40 + udpsize
						binary.BigEndian.PutUint16(rawbuf[4:], uint16(udpsize))
						copy(rawbuf[8:], packet.Raw[24:40])
						copy(rawbuf[24:], packet.Raw[8:24])
						copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
						copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
					} else {
						copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
						packetsize = 20 + udpsize
						binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
						copy(rawbuf[12:], packet.Raw[16:20])
						copy(rawbuf[16:], packet.Raw[12:16])
						copy(rawbuf[20:], packet.Raw[ipheadlen+2:ipheadlen+4])
						copy(rawbuf[22:], packet.Raw[ipheadlen:ipheadlen+2])
						ipheadlen = 20
					}

					binary.BigEndian.PutUint16(rawbuf[ipheadlen+4:], uint16(udpsize))
					copy(rawbuf[ipheadlen+8:], request)
					rawbuf[ipheadlen+10] = 0x81
					rawbuf[ipheadlen+11] = 0x80
					binary.BigEndian.PutUint16(rawbuf[ipheadlen+14:], anCount)
					copy(rawbuf[ipheadlen+8+len(request):], answers)

					packet.PacketLen = uint(packetsize)
					packet.Raw = rawbuf[:packetsize]
					packet.CalcNewChecksum(winDivert)

					_, err = winDivert.Send(packet)
				} else if !LocalDNS {
					logPrintln(qname, config.Option)
					go func(level int, answers6 []byte, offset int) {
						rawbuf := make([]byte, 1500)
						if ipv6 {
							copy(rawbuf, []byte{96, 12, 19, 68, 0, 98, 17, 128})
							copy(rawbuf[8:], packet.Raw[24:40])
							copy(rawbuf[24:], packet.Raw[8:24])
							copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
							copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
						} else {
							copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
							copy(rawbuf[12:], packet.Raw[16:20])
							copy(rawbuf[16:], packet.Raw[12:16])
							copy(rawbuf[20:], packet.Raw[ipheadlen+2:ipheadlen+4])
							copy(rawbuf[22:], packet.Raw[ipheadlen:ipheadlen+2])
							ipheadlen = 20
						}

						var response []byte
						var err error
						if qtype != 28 || answers6 == nil {
							response, err = TCPlookup(packet.Raw[ipheadlen+udpheadlen:], DNS)
						} else {
							if DNS64 == "" {
								response, err = TCPlookupDNS64(packet.Raw[ipheadlen+udpheadlen:], DNS, offset, answers6)
							} else {
								response, err = TCPlookup(packet.Raw[ipheadlen+udpheadlen:], DNS64)
								//response, err = TCPlookupDNS64(packet.Raw[ipheadlen+udpheadlen:], DNS64, offset, answers6)
							}
						}
						if err != nil {
							if LogLevel > 1 || !ServiceMode {
								log.Println(err)
							}
							return
						}
						if response == nil {
							return
						}

						count := int(binary.BigEndian.Uint16(response[6:8]))
						ips := getAnswers(response[off:], count)
						for _, ip := range ips {
							_, ok := IPMap[ip]
							if ok == false {
								IPMap[ip] = IPConfig{config.Option, config.TTL, config.MAXTTL, config.MSS}
							}
						}

						udpsize := len(response) + 8
						var packetsize int
						if ipv6 {
							packetsize = 40 + udpsize
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(udpsize))
						} else {
							packetsize = 20 + udpsize
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
						}

						binary.BigEndian.PutUint16(rawbuf[ipheadlen+4:], uint16(udpsize))
						copy(rawbuf[ipheadlen+8:], response)

						packet.PacketLen = uint(packetsize)
						packet.Raw = rawbuf[:packetsize]
						packet.CalcNewChecksum(winDivert)

						_, err = winDivert.Send(packet)
					}(int(config.Option), config.Answers6, off)
				}
			}
		} else {
			_, err = winDivert.Send(packet)
		}
	}
}

func DNSRecvDaemon() {
	filter := "((outbound and loopback) or inbound) and udp.SrcPort == 53"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			if LogLevel > 1 || !ServiceMode {
				log.Println(err)
			}
			return
		}

		ipv6 := packet.Raw[0]>>4 == 6

		var ipheadlen int
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(packet.Raw[0]&0xF) * 4
		}

		udpheadlen := 8
		qname, qtype, off := getQName(packet.Raw[ipheadlen+udpheadlen:])
		if qname == "" {
			logPrintln("DNS Segmentation fault")
			continue
		}

		config := domainLookup(qname)

		if config.Option > 1 && qtype == 1 {
			logPrintln(qname, "LEVEL", config.Option)
			response := packet.Raw[ipheadlen+udpheadlen:]
			count := int(binary.BigEndian.Uint16(response[6:8]))
			ips := getAnswers(response[off:], count)

			for _, ip := range ips {
				IPMap[ip] = IPConfig{config.Option, config.TTL, config.MAXTTL, config.MSS}
			}
		}
		_, err = winDivert.Send(packet)
	}
}

func getSNI(b []byte) (offset int, length int) {
	if b[0] != 0x16 {
		return 0, 0
	}
	if len(b) < 5 {
		return 0, 0
	}
	Version := binary.BigEndian.Uint16(b[1:3])
	if (Version & 0xFFF8) != 0x0300 {
		return 0, 0
	}
	Length := binary.BigEndian.Uint16(b[3:5])
	if len(b) <= int(Length)-5 {
		return 0, 0
	}
	offset = 11 + 32
	SessionIDLength := b[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 > len(b) {
		return 0, 0
	}
	CipherSuitersLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= len(b) {
		return 0, 0
	}
	CompressionMethodsLenght := b[offset]
	offset += 1 + int(CompressionMethodsLenght)
	if offset+2 > len(b) {
		return 0, 0
	}
	ExtensionsLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	if ExtensionsEnd > len(b) {
		return 0, 0
	}
	for offset < ExtensionsEnd {
		ExtensionType := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		if ExtensionType == 0 {
			offset += 2
			offset++
			ServerNameLength := binary.BigEndian.Uint16(b[offset : offset+2])
			offset += 2
			return offset, int(ServerNameLength)
		} else {
			offset += int(ExtensionLength)
		}
	}
	return 0, 0
}

func getHost(b []byte) (offset int, length int) {
	offset = bytes.Index(b, []byte("Host: "))
	if offset == -1 {
		return 0, 0
	}
	length = bytes.Index(b[offset:], []byte("\r\n"))
	if offset == -1 {
		return 0, 0
	}

	return
}

func UDPDaemon(dstPort int) {
	filter := "outbound and !loopback and udp.DstPort == " + strconv.Itoa(dstPort)
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			if LogLevel > 0 || !ServiceMode {
				log.Println(err)
			}
			return
		}

		_, ok := IPMap[packet.DstIP().String()]
		if !ok {
			_, err = winDivert.Send(packet)
			if err != nil {
				if LogLevel > 0 || !ServiceMode {
					log.Println(err)
				}
				return
			}
		}
	}
}

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

func TFODaemon(srcAddr string, srcPort int) {
	filter := fmt.Sprintf("inbound and ip.SrcAddr = %s and tcp.SrcPort == %d", srcAddr, srcPort)
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			if LogLevel > 0 || !ServiceMode {
				log.Println(err)
			}
			continue
		}

		ipv6 := packet.Raw[0]>>4 == 6
		var ipheadlen int
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(packet.Raw[0]&0xF) * 4
		}

		dstPort := binary.BigEndian.Uint16(packet.Raw[ipheadlen+2:])

		if packet.Raw[ipheadlen+13] == TCP_SYN|TCP_ACK {
			var info *ConnInfo
			if ipv6 {
				info = PortList6[dstPort]
			} else {
				info = PortList4[dstPort]
			}

			info.AckNum = binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
			binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], 0)
			tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4

			optStart := ipheadlen + 20
			option := packet.Raw[optStart : ipheadlen+tcpheadlen]
			cookies := getCookies(option)
			if cookies != nil {
				tmp_option := make([]byte, len(option))
				copy(tmp_option, option)
				OptionMap[srcAddr] = tmp_option
			} else {
				ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:])
				if ackNum > info.SeqNum {
					rawbuf[ipheadlen+13] = TCP_ACK
				} else {
					rawbuf[ipheadlen+13] = TCP_ACK | TCP_RST
					delete(OptionMap, packet.SrcIP().String())
				}
				packet.Raw[ipheadlen+12] = 5 << 4
				packet.Raw = packet.Raw[:ipheadlen+20]
				packet.PacketLen = uint(ipheadlen + 20)
				if ipv6 {
					binary.BigEndian.PutUint16(packet.Raw[4:], uint16(packet.PacketLen))
				} else {
					binary.BigEndian.PutUint16(packet.Raw[2:], uint16(packet.PacketLen))
				}
			}
			packet.CalcNewChecksum(winDivert)
		} else {
			var info *ConnInfo
			if ipv6 {
				info = PortList6[dstPort]
			} else {
				info = PortList4[dstPort]
			}
			if info == nil {
				continue
			}
			seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
			seqNum -= info.AckNum
			binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], seqNum)
			packet.CalcNewChecksum(winDivert)
		}

		_, err = winDivert.Send(packet)
		if err != nil {
			if LogLevel > 0 || !ServiceMode {
				log.Println(err)
			}
		}
	}
}

func TCPDaemon(address string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err)
		}
		return
	}

	var filter string
	if address[0] == ':' {
		filter = fmt.Sprintf("!loopback and outbound and tcp.DstPort == %s", address[1:])
	} else {
		filter = fmt.Sprintf("outbound and ip.DstAddr = %s and tcp.DstPort == %d", tcpAddr.IP.String(), tcpAddr.Port)
	}

	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			if LogLevel > 0 || !ServiceMode {
				log.Println(err)
			}
			continue
		}

		ipv6 := packet.Raw[0]>>4 == 6
		var ipheadlen int
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(packet.Raw[0]&0xF) * 4
		}
		srcPort := int(binary.BigEndian.Uint16(packet.Raw[ipheadlen:]))

		if (packet.Raw[ipheadlen+13] & TCP_PSH) != 0 {
			var info *ConnInfo
			if ipv6 {
				info = PortList6[srcPort]
			} else {
				info = PortList4[srcPort]
			}

			if info == nil {
				_, err = winDivert.Send(packet)
				if err != nil {
					if LogLevel > 0 || !ServiceMode {
						log.Println(err)
					}
				}
				continue
			}

			tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
			dstPort := int(binary.BigEndian.Uint16(packet.Raw[ipheadlen+2:]))

			host_offset := 0
			host_length := 0
			switch dstPort {
			case 53:
				if len(packet.Raw[ipheadlen+tcpheadlen:]) > 21 {
					host_offset = 20
					host_length = 1
				}
			case 80:
				host_offset, host_length = getHost(packet.Raw[ipheadlen+tcpheadlen:])
			case 443:
				if info.Option&OPT_TFO != 0 {
					seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
					if seqNum == info.SeqNum+1 {
						var synOption []byte
						if ipv6 {
							synOption = SynOption6
						} else {
							synOption = SynOption4
						}

						if synOption == nil {
							continue
						}
						dstAddr := packet.DstIP().String()
						option, ok := OptionMap[dstAddr]
						if !ok {
							continue
						}
						copy(rawbuf, packet.Raw[:ipheadlen+20])
						binary.BigEndian.PutUint32(rawbuf[ipheadlen+4:], info.SeqNum)
						binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], 0)

						copy(rawbuf[ipheadlen+20:], synOption)
						optLen := len(synOption)
						packet.PacketLen = uint(ipheadlen + 20 + optLen)
						offset := 5 + byte(optLen/4)
						rawbuf[ipheadlen+12] = offset << 4
						rawbuf[ipheadlen+13] = TCP_SYN

						if (info.Option & OPT_MSS) != 0 {
							if tcpheadlen >= 24 {
								tcpOption := rawbuf[ipheadlen+20]
								if tcpOption == 2 {
									config, ok := IPMap[dstAddr]
									if ok {
										binary.BigEndian.PutUint16(rawbuf[ipheadlen+22:], config.MSS)
									}
								}
							}
						}

						cookies := getCookies(option)
						cookiesLen := len(cookies)
						optLen = cookiesLen + 2
						offset = byte((optLen + 3) / 4)
						rawbuf[ipheadlen+12] += offset << 4
						rawbuf[int(packet.PacketLen)] = 34
						rawbuf[int(packet.PacketLen)+1] = byte(optLen)
						copy(rawbuf[int(packet.PacketLen)+2:], cookies)

						blankoffset := packet.PacketLen + uint(offset*4)
						packet.PacketLen += uint(optLen)
						for i := packet.PacketLen; i < blankoffset; i++ {
							rawbuf[i] = 1
						}
						packet.PacketLen = blankoffset
						copy(rawbuf[packet.PacketLen:], packet.Raw[ipheadlen+tcpheadlen:])
						packet.PacketLen += uint(len(packet.Raw[ipheadlen+tcpheadlen:]))

						if ipv6 {
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(packet.PacketLen))
						} else {
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
						}

						packet.Raw = rawbuf[:packet.PacketLen]
					} else {
						ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:])
						ackNum += info.AckNum
						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], ackNum)
					}
					packet.CalcNewChecksum(winDivert)
				} else {
					host_offset, host_length = getSNI(packet.Raw[ipheadlen+tcpheadlen:])

					if ipv6 {
						PortList6[srcPort] = nil
					} else {
						PortList4[srcPort] = nil
					}
				}
			default:
				host_length = len(packet.Raw[ipheadlen+tcpheadlen:])
			}

			if host_length > 0 {
				fake_packet := *packet
				copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])

				if info.TTL > 0 {
					if ipv6 {
						rawbuf[7] = byte(info.TTL)
					} else {
						rawbuf[8] = byte(info.TTL)
					}
				}

				if (info.Option & OPT_MD5) != 0 {
					copy(rawbuf[ipheadlen+20:], []byte{19, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
					rawbuf[ipheadlen+12] = 10 << 4
				}

				if (info.Option & OPT_ACK) != 0 {
					ackNum := binary.BigEndian.Uint32(rawbuf[ipheadlen+8:])
					ackNum += uint32(binary.BigEndian.Uint16(rawbuf[ipheadlen+14:]))
					binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], ackNum)
				}

				if (info.Option & OPT_SYN) != 0 {
					rawbuf[ipheadlen+13] = TCP_SYN

					seqNum := binary.BigEndian.Uint32(rawbuf[ipheadlen+4:])
					seqNum += 65536
					binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], seqNum)
					if (info.Option & OPT_ACK) != 0 {
						rawbuf[ipheadlen+13] |= TCP_ACK
					} else {
						binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], 0)
					}
				}

				fake_packet.Raw = rawbuf[:len(packet.Raw)]
				fake_packet.CalcNewChecksum(winDivert)

				if (info.Option & OPT_CSUM) != 0 {
					binary.BigEndian.PutUint16(rawbuf[ipheadlen+16:], 0)
				}

				if (info.Option & (OPT_ACK | OPT_SYN)) == 0 {
					_, err = winDivert.Send(&fake_packet)
					if err != nil {
						if LogLevel > 0 || !ServiceMode {
							log.Println(err)
						}
						continue
					}
				}

				host_cut_offset := host_offset + host_length/2
				total_cut_offset := ipheadlen + tcpheadlen + host_cut_offset

				tmp_rawbuf := make([]byte, 1500)
				copy(tmp_rawbuf, packet.Raw[:total_cut_offset])
				if ipv6 {
					binary.BigEndian.PutUint16(tmp_rawbuf[4:], uint16(total_cut_offset-ipheadlen))
					if info.MAXTTL > 0 {
						tmp_rawbuf[7] = info.MAXTTL
					}
				} else {
					binary.BigEndian.PutUint16(tmp_rawbuf[2:], uint16(total_cut_offset))
					if info.MAXTTL > 0 {
						tmp_rawbuf[8] = info.MAXTTL
					}
				}
				tmp_rawbuf[ipheadlen+13] &= ^TCP_PSH

				prefix_packet := *packet
				prefix_packet.Raw = tmp_rawbuf[:total_cut_offset]
				prefix_packet.PacketLen = uint(total_cut_offset)
				prefix_packet.CalcNewChecksum(winDivert)
				_, err = winDivert.Send(&prefix_packet)
				if err != nil {
					if LogLevel > 0 || !ServiceMode {
						log.Println(err)
					}
					continue
				}

				if (info.Option & (OPT_ACK | OPT_SYN)) != 0 {
					_, err = winDivert.Send(&fake_packet)
					if err != nil {
						if LogLevel > 0 || !ServiceMode {
							log.Println(err)
						}
						continue
					}
					time.Sleep(time.Microsecond * 10)
				}

				_, err = winDivert.Send(&fake_packet)
				if err != nil {
					if LogLevel > 0 || !ServiceMode {
						log.Println(err)
					}
					continue
				}

				seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4 : ipheadlen+8])
				copy(tmp_rawbuf, packet.Raw[:ipheadlen+tcpheadlen])
				copy(tmp_rawbuf[ipheadlen+tcpheadlen:], packet.Raw[total_cut_offset:])
				totallen := uint16(packet.PacketLen) - uint16(host_cut_offset)
				if ipv6 {
					binary.BigEndian.PutUint16(tmp_rawbuf[4:], totallen-uint16(ipheadlen))
					if info.MAXTTL > 0 {
						tmp_rawbuf[7] = info.MAXTTL + 1
					}
				} else {
					binary.BigEndian.PutUint16(tmp_rawbuf[2:], totallen)
					if info.MAXTTL > 0 {
						tmp_rawbuf[8] = info.MAXTTL + 1
					}
				}
				binary.BigEndian.PutUint32(tmp_rawbuf[ipheadlen+4:], seqNum+uint32(host_cut_offset))
				packet.Raw = tmp_rawbuf[:totallen]
				packet.PacketLen = uint(totallen)
				packet.CalcNewChecksum(winDivert)

				_, err = winDivert.Send(packet)
				if err != nil {
					if LogLevel > 0 || !ServiceMode {
						log.Println(err)
					}
					continue
				}
			} else {
				_, err = winDivert.Send(packet)
				if err != nil {
					if LogLevel > 0 || !ServiceMode {
						log.Println(err)
					}
					continue
				}
			}
		} else if packet.Raw[ipheadlen+13] == TCP_SYN {
			dstAddr := packet.DstIP().String()
			config, ok := IPMap[dstAddr]

			if ok {
				if config.Option != 0 {
					if ipv6 {
						PortList6[srcPort] = &ConnInfo{config.Option, 0, 0, config.TTL, config.MAXTTL}
					} else {
						PortList4[srcPort] = &ConnInfo{config.Option, 0, 0, config.TTL, config.MAXTTL}
					}

					tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4

					if (config.Option & OPT_TFO) != 0 {
						synOption := make([]byte, tcpheadlen-20)
						copy(synOption, packet.Raw[ipheadlen+20:])

						copy(rawbuf, packet.Raw)
						option, ok := OptionMap[dstAddr]

						seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
						if option != nil {
							if ipv6 {
								copy(rawbuf[8:], packet.Raw[24:40])
								copy(rawbuf[24:], packet.Raw[8:24])
							} else {
								copy(rawbuf[12:], packet.Raw[16:20])
								copy(rawbuf[16:], packet.Raw[12:16])
							}
							copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
							copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
							binary.BigEndian.PutUint32(rawbuf[ipheadlen+4:], 0)
							binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], seqNum+1)

							rawbuf[ipheadlen+13] = TCP_SYN | TCP_ACK

							copy(rawbuf[ipheadlen+20:], option)
							packet.PacketLen += uint(len(option))
							rawbuf[ipheadlen+12] += byte(len(option)/4) << 4
						} else {
							if !ok {
								OptionMap[dstAddr] = nil
								go TFODaemon(dstAddr, tcpAddr.Port)
							}
							packet.PacketLen += 4
							rawbuf[ipheadlen+12] += 1 << 4
							rawbuf[ipheadlen+tcpheadlen] = 34
							rawbuf[ipheadlen+tcpheadlen+1] = 2
							rawbuf[ipheadlen+tcpheadlen+2] = 1
							rawbuf[ipheadlen+tcpheadlen+3] = 1
						}

						if ipv6 {
							PortList6[srcPort].SeqNum = seqNum
							SynOption6 = synOption
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(packet.PacketLen))
						} else {
							PortList4[srcPort].SeqNum = seqNum
							SynOption4 = synOption
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
						}

						packet.Raw = rawbuf[:packet.PacketLen]

						packet.CalcNewChecksum(winDivert)
					} else if (config.Option & OPT_MSS) != 0 {
						if tcpheadlen >= 24 {
							tcpOption := packet.Raw[ipheadlen+20]
							if tcpOption == 2 {
								binary.BigEndian.PutUint16(packet.Raw[ipheadlen+22:], config.MSS)
								packet.CalcNewChecksum(winDivert)
							}
						}
					}

					logPrintln(packet.DstIP(), config.Option)
				}
			} else {
				if ipv6 {
					PortList6[srcPort] = nil
				} else {
					PortList4[srcPort] = nil
				}
			}

			_, err = winDivert.Send(packet)
			if err != nil {
				if LogLevel > 0 || !ServiceMode {
					log.Println(err)
				}
			}
		} else if (packet.Raw[ipheadlen+13] & TCP_ACK) != 0 {
			var info *ConnInfo
			if ipv6 {
				info = PortList6[srcPort]
			} else {
				info = PortList4[srcPort]
			}

			if info != nil {
				if info.Option&OPT_TFO != 0 {
					seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])

					ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:])
					ackNum += info.AckNum
					binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], ackNum)

					if seqNum == info.SeqNum+1 {
						if ackNum == 1 && info.AckNum == 0 {
							continue
						}

						packet.Raw[ipheadlen+12] = 5 << 4
						packet.Raw[ipheadlen+13] = TCP_RST | TCP_ACK
						packet.PacketLen = uint(ipheadlen + 20)
						if ipv6 {
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(packet.PacketLen))
						} else {
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
						}
						packet.CalcNewChecksum(winDivert)

						_, err = winDivert.Send(packet)
						if err != nil {
							if LogLevel > 0 || !ServiceMode {
								log.Println(err)
							}
						}

						packet.Raw[ipheadlen+13] = TCP_RST
						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], 0)
					}

					packet.CalcNewChecksum(winDivert)
				}
			}

			_, err = winDivert.Send(packet)
			if err != nil {
				if LogLevel > 0 || !ServiceMode {
					log.Println(err)
				}
			}
		} else {
			_, err = winDivert.Send(packet)
			if err != nil {
				if LogLevel > 0 || !ServiceMode {
					log.Println(err)
				}
			}
		}
	}
}

func getMyIPv6() net.IP {
	s, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range s {
		strIP := strings.SplitN(a.String(), "/", 2)
		if strIP[1] == "128" && strIP[0] != "::1" {
			ip := net.ParseIP(strIP[0])
			ip4 := ip.To4()
			if ip4 == nil {
				return ip
			}
		}
	}
	return nil
}

func NAT64(ipv6 net.IP, ipv4 net.IP) {
	copy(ipv6[12:], ipv4[:4])
	filter := "!loopback and ((outbound and ip.DstAddr=" + ipv4.String() + ") or (inbound and ipv6.SrcAddr=" + ipv6.String() + "))"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

	myIPv6 := getMyIPv6()
	if myIPv6 == nil {
		return
	}

	rawbuf := make([]byte, 1500)
	srcIP := make([]byte, 4)

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			if LogLevel > 0 || !ServiceMode {
				log.Println(err)
			}
			return
		}

		ipVer := packet.Raw[0] >> 4

		if ipVer == 4 {
			ipheadlen := int(packet.Raw[0]&0xF) * 4
			payloadLen := int(packet.PacketLen) - ipheadlen

			copy(srcIP, packet.Raw[12:16])

			copy(rawbuf, []byte{0x60, 0x00, 0x00, 0x00})
			binary.BigEndian.PutUint16(rawbuf[4:], uint16(payloadLen))
			rawbuf[6] = packet.Raw[9]
			rawbuf[7] = packet.Raw[8]
			copy(rawbuf[8:], myIPv6[:16])
			copy(rawbuf[24:], ipv6[:16])
			copy(rawbuf[40:], packet.Raw[ipheadlen:])

			packet6 := *packet
			packet6.Raw = rawbuf[:40+payloadLen]
			packet6.PacketLen = uint(payloadLen + 40)
			packet6.CalcNewChecksum(winDivert)

			_, err = winDivert.Send(&packet6)
		} else if ipVer == 6 {
			ipheadlen := 40
			payloadLen := int(packet.PacketLen) - ipheadlen

			copy(rawbuf, []byte{0x45, 0x00})
			binary.BigEndian.PutUint16(rawbuf[2:], uint16(20+payloadLen))
			copy(rawbuf[4:], []byte{0x00, 0x00})
			copy(rawbuf[6:], []byte{0x40, 0x00})
			rawbuf[8] = packet.Raw[7]
			rawbuf[9] = packet.Raw[6]
			copy(rawbuf[10:], []byte{0x00, 0x00})
			copy(rawbuf[12:], ipv4)
			copy(rawbuf[16:], srcIP)
			copy(rawbuf[20:], packet.Raw[ipheadlen:])

			packet4 := *packet
			packet4.Raw = rawbuf[:20+payloadLen]
			packet4.PacketLen = uint(20 + payloadLen)
			packet4.CalcNewChecksum(winDivert)

			_, err = winDivert.Send(&packet4)
		}

		if err != nil {
			if LogLevel > 0 || !ServiceMode {
				log.Println(err)
			}
			return
		}
	}
}

func loadConfig() error {
	DomainMap = make(map[string]Config)
	IPMap = make(map[string]IPConfig)
	OptionMap = make(map[string][]byte)
	conf, err := os.Open("config")
	if err != nil {
		return err
	}
	defer conf.Close()

	br := bufio.NewReader(conf)

	var option uint32 = 0
	var minTTL byte = 0
	var maxTTL byte = 0
	var syncMSS uint16 = 0

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if len(line) > 0 {
			if line[0] != '#' {
				keys := strings.SplitN(string(line), "=", 2)
				if len(keys) > 1 {
					if keys[0] == "server" {
						DNS = keys[1]
						tcpAddr, err := net.ResolveTCPAddr("tcp", keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						IPMap[tcpAddr.IP.String()] = IPConfig{option, minTTL, maxTTL, syncMSS}
						logPrintln(string(line))
					} else if keys[0] == "dns64" {
						DNS64 = keys[1]
						logPrintln(string(line))
					} else if keys[0] == "ttl" {
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						if ttl == 0 {
							option &= ^uint32(OPT_TTL)
						} else {
							option |= OPT_TTL
						}
						minTTL = byte(ttl)
						logPrintln(string(line))
					} else if keys[0] == "mss" {
						mss, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						if mss == 0 {
							option &= ^uint32(OPT_MSS)
						} else {
							option |= OPT_MSS
						}
						syncMSS = uint16(mss)
						logPrintln(string(line))
					} else if keys[0] == "md5" {
						if keys[1] == "true" {
							option |= OPT_MD5
						} else {
							option &= ^uint32(OPT_MD5)
						}
						logPrintln(string(line))
					} else if keys[0] == "ack" {
						if keys[1] == "true" {
							option |= OPT_ACK
						} else {
							option &= ^uint32(OPT_ACK)
						}
						logPrintln(string(line))
					} else if keys[0] == "syn" {
						if keys[1] == "true" {
							option |= OPT_SYN
						} else {
							option &= ^uint32(OPT_SYN)
						}
						logPrintln(string(line))
					} else if keys[0] == "checksum" {
						if keys[1] == "true" {
							option |= OPT_CSUM
						} else {
							option &= ^uint32(OPT_CSUM)
						}
						logPrintln(string(line))
					} else if keys[0] == "tcpfastopen" {
						if keys[1] == "true" {
							option |= OPT_TFO
						} else {
							option &= ^uint32(OPT_TFO)
						}
						logPrintln(string(line))
					} else if keys[0] == "max-ttl" {
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						maxTTL = byte(ttl)
						logPrintln(string(line))
					} else if keys[0] == "log" {
						LogLevel, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
					} else {
						ip := net.ParseIP(keys[0])
						if ip == nil {
							if strings.HasSuffix(keys[1], "::") {
								prefix := net.ParseIP(keys[1])
								if prefix != nil {
									DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS, 0, 0, nil, prefix}
								}
							} else {
								ips := strings.Split(keys[1], ",")
								for _, ip := range ips {
									config, ok := IPMap[ip]
									if ok {
										option |= config.Option
										if syncMSS == 0 {
											syncMSS = config.MSS
										}
									}
									IPMap[ip] = IPConfig{option, minTTL, maxTTL, syncMSS}
								}
								count4, answer4 := packAnswers(ips, 1)
								count6, answer6 := packAnswers(ips, 28)
								DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS, uint16(count4), uint16(count6), answer4, answer6}
							}
						} else {
							prefix := net.ParseIP(keys[1])
							ip4 := ip.To4()
							if ip4 != nil {
								go NAT64(prefix, ip4)
							}
						}
					}
				} else {
					if keys[0] == "local-dns" {
						LocalDNS = true
						logPrintln("local-dns")
					} else if keys[0] == "ipv6" {
						IPv6Enable = true
						logPrintln(string(line))
					} else {
						addr, err := net.ResolveTCPAddr("tcp", keys[0])
						if err == nil {
							IPMap[addr.IP.String()] = IPConfig{option, minTTL, maxTTL, syncMSS}
							go TCPDaemon(keys[0])
						} else {
							DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS, 0, 0, nil, nil}
						}
					}
				}
			}
		}
	}

	return nil
}

func StartService() {
	runtime.GOMAXPROCS(1)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if LogLevel > 0 {
		var logFilename string = "tcpioneer.log"
		logFile, err := os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE, 0777)
		if err != nil {
			log.Println(err)
			return
		}
		defer logFile.Close()

		Logger = log.New(logFile, "\r\n", log.Ldate|log.Ltime|log.Lshortfile)
	}

	err := loadConfig()
	if err != nil {
		if LogLevel > 0 || !ServiceMode {
			log.Println(err)
		}
		return
	}

	go DNSDaemon()
	if LocalDNS {
		go DNSRecvDaemon()
	} else {
		go TCPDaemon(DNS)
	}

	go TCPDaemon(":80")
	go UDPDaemon(443)
	TCPDaemon(":443")
}

func StopService() {
	arg := []string{"/flushdns"}
	cmd := exec.Command("ipconfig", arg...)
	d, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(d), err)
	}

	os.Exit(0)
}

func main() {
	serviceName := "TCPPioneer"
	var flagServiceInstall bool
	var flagServiceUninstall bool
	var flagServiceStart bool
	var flagServiceStop bool
	flag.BoolVar(&flagServiceInstall, "install", false, "Install service")
	flag.BoolVar(&flagServiceUninstall, "remove", false, "Remove service")
	flag.BoolVar(&flagServiceStart, "start", false, "Start service")
	flag.BoolVar(&flagServiceStop, "stop", false, "Stop service")
	flag.Parse()

	appPath, err := winsvc.GetAppPath()
	if err != nil {
		log.Fatal(err)
	}

	// install service
	if flagServiceInstall {
		if err := winsvc.InstallService(appPath, serviceName, ""); err != nil {
			log.Fatalf("installService(%s, %s): %v\n", serviceName, "", err)
		}
		log.Printf("Done\n")
		return
	}

	// remove service
	if flagServiceUninstall {
		if err := winsvc.RemoveService(serviceName); err != nil {
			log.Fatalln("removeService:", err)
		}
		log.Printf("Done\n")
		return
	}

	// start service
	if flagServiceStart {
		if err := winsvc.StartService(serviceName); err != nil {
			log.Fatalln("startService:", err)
		}
		log.Printf("Done\n")
		return
	}

	// stop service
	if flagServiceStop {
		if err := winsvc.StopService(serviceName); err != nil {
			log.Fatalln("stopService:", err)
		}
		log.Printf("Done\n")
		return
	}

	// run as service
	if !winsvc.IsAnInteractiveSession() {
		log.Println("main:", "runService")

		if err := os.Chdir(filepath.Dir(appPath)); err != nil {
			log.Fatal(err)
		}

		if err := winsvc.RunAsService(serviceName, StartService, StopService, false); err != nil {
			log.Fatalf("svc.Run: %v\n", err)
		}
		return
	}

	ServiceMode = false
	StartService()
}
