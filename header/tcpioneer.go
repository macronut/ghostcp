package tcpioneer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
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

var DomainMap map[string]Config
var IPMap map[string]IPConfig
var wg sync.WaitGroup

var IPv6Enable = false
var LogLevel = 0
var Forward bool = false

const (
	OPT_TTL   = 0x001
	OPT_MSS   = 0x002
	OPT_MD5   = 0x004
	OPT_ACK   = 0x008
	OPT_SYN   = 0x010
	OPT_CSUM  = 0x020
	OPT_TFO   = 0x040
	OPT_BAD   = 0x080
	OPT_IPOPT = 0x100
	OPT_PSH   = 0x200
)

var Logger *log.Logger

func logPrintln(level int, v ...interface{}) {
	if LogLevel >= level {
		fmt.Println(v)
	}
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

func LoadConfig() error {
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
						logPrintln(2, string(line))
					} else if keys[0] == "dns64" {
						DNS64 = keys[1]
						logPrintln(2, string(line))
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
						logPrintln(2, string(line))
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
						logPrintln(2, string(line))
					} else if keys[0] == "md5" {
						if keys[1] == "true" {
							option |= OPT_MD5
						} else {
							option &= ^uint32(OPT_MD5)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "ack" {
						if keys[1] == "true" {
							option |= OPT_ACK
						} else {
							option &= ^uint32(OPT_ACK)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "syn" {
						if keys[1] == "true" {
							option |= OPT_SYN
						} else {
							option &= ^uint32(OPT_SYN)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "checksum" {
						if keys[1] == "true" {
							option |= OPT_CSUM
						} else {
							option &= ^uint32(OPT_CSUM)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "tcpfastopen" {
						if keys[1] == "true" {
							option |= OPT_TFO
						} else {
							option &= ^uint32(OPT_TFO)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "bad" {
						if keys[1] == "true" {
							option |= OPT_BAD
						} else {
							option &= ^uint32(OPT_BAD)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "ipoption" {
						if keys[1] == "true" {
							option |= OPT_IPOPT
						} else {
							option &= ^uint32(OPT_IPOPT)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "psh" {
						if keys[1] == "true" {
							option |= OPT_PSH
						} else {
							option &= ^uint32(OPT_PSH)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "max-ttl" {
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						maxTTL = byte(ttl)
						logPrintln(2, string(line))
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
								if Forward {
									go NAT64(prefix, ip4, true)
								}
								go NAT64(prefix, ip4, false)
							}
						}
					}
				} else {
					if keys[0] == "ipv6" {
						IPv6Enable = true
						logPrintln(2, string(line))
					} else if keys[0] == "forward" {
						Forward = true
						logPrintln(2, string(line))
					} else {
						addr, err := net.ResolveTCPAddr("tcp", keys[0])
						if err == nil {
							IPMap[addr.IP.String()] = IPConfig{option, minTTL, maxTTL, syncMSS}
							if Forward {
								go TCPDaemon(keys[0], true)
							}
							go TCPDaemon(keys[0], false)
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

func Wait() {
	wg.Wait()
}
