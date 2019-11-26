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
	ANCount4 int16
	ANCount6 int16
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

var SubdomainDepth = 2
var LogLevel = 0
var Forward bool = false
var IPBlock = false
var IPMode = false
var TFOEnable = false

const (
	OPT_TTL    = 0x001
	OPT_MSS    = 0x002
	OPT_MD5    = 0x004
	OPT_ACK    = 0x008
	OPT_CSUM   = 0x010
	OPT_BAD    = 0x020
	OPT_IPOPT  = 0x040
	OPT_SEQ    = 0x080
	OPT_HTTPS  = 0x100
	OPT_TFO    = 0x10000
	OPT_SYN    = 0x20000
	OPT_NOFLAG = 0x40000
	OPT_QUIC   = 0x80000
)

var Logger *log.Logger

func logPrintln(level int, v ...interface{}) {
	if LogLevel >= level {
		fmt.Println(v)
	}
}

func domainLookup(qname string) (Config, bool) {
	config, ok := DomainMap[qname]
	if ok {
		return config, true
	}

	if SubdomainDepth == 0 {
		return Config{0, 0, 0, 0, 0, 0, nil, nil}, true
	}

	offset := 0
	for i := 0; i < SubdomainDepth; i++ {
		off := strings.Index(qname[offset:], ".")
		if off == -1 {
			break
		}
		offset += off
		config, ok = DomainMap[qname[offset:]]
		if ok {
			return config, true
		}
		offset++
	}

	return Config{0, 0, 0, 0, 0, 0, nil, nil}, false
}

func IPLookup(addr string) (IPConfig, bool) {
	config, ok := IPMap[addr]
	if ok {
		return config, true
	}

	if IPMode {
		ip := net.ParseIP(addr)
		ip4 := ip.To4()
		if ip4 != nil {
			for i := 31; i >= 8; i-- {
				mask := net.CIDRMask(i, 32)
				addr := fmt.Sprintf("%s/%d", ip.Mask(mask).String(), i)
				config, ok = IPMap[addr]
				if ok {
					return config, true
				}
			}
		} else {
			for i := 64; i >= 16; i -= 16 {
				mask := net.CIDRMask(i, 32)
				addr := fmt.Sprintf("%s/%d", ip.Mask(mask).String(), i)
				config, ok = IPMap[addr]
				if ok {
					return config, true
				}
			}
		}

		config, ok := IPMap["0.0.0.0/0"]
		return config, ok
	}

	return config, false
}

func IPBlockLookup(addr string) (IPConfig, bool) {
	var config IPConfig
	ok := false

	ip := net.ParseIP(addr)
	ip4 := ip.To4()
	if ip4 != nil {
		for i := 31; i >= 8; i-- {
			mask := net.CIDRMask(i, 32)
			addr := fmt.Sprintf("%s/%d", ip.Mask(mask).String(), i)
			config, ok = IPMap[addr]
			if ok {
				return config, true
			}
		}
	} else {
		for i := 64; i >= 16; i -= 16 {
			mask := net.CIDRMask(i, 32)
			addr := fmt.Sprintf("%s/%d", ip.Mask(mask).String(), i)
			config, ok = IPMap[addr]
			if ok {
				return config, true
			}
		}
	}

	config, ok = IPMap["0.0.0.0/0"]
	return config, ok
}

func getSNI(b []byte) (offset int, length int) {
	payloadLen := len(b)
	if payloadLen < 11+32 {
		return 0, 0
	}
	if b[0] != 0x16 {
		return 0, 0
	}
	version := binary.BigEndian.Uint16(b[1:3])
	if (version & 0xFFF8) != 0x0300 {
		return 0, 0
	}
	handshakeType := b[5]
	if handshakeType != 0x1 {
		return 0, 0
	}
	//Length := binary.BigEndian.Uint16(b[3:5])
	//version = binary.BigEndian.Uint16(b[9:11])
	offset = 11 + 32
	SessionIDLength := b[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 >= payloadLen {
		return 0, 0
	}
	CipherSuitersLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= payloadLen {
		return 0, 0
	}
	CompressionMethodsLenght := b[offset]
	offset += 1 + int(CompressionMethodsLenght)
	if offset+2 > payloadLen {
		return 0, 0
	}
	ExtensionsLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	for offset < ExtensionsEnd {
		if offset+4 > payloadLen {
			return 0, 0
		}
		ExtensionType := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		if ExtensionType == 0 {
			offset += 2
			offset++
			if offset+2 > payloadLen {
				return 0, 0
			}
			ServerNameLength := binary.BigEndian.Uint16(b[offset : offset+2])
			offset += 2
			if offset+int(ServerNameLength) > payloadLen {
				return offset, payloadLen - offset
			}
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
	offset += 6
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
	ipv6Enable := true
	ipv4Enable := true

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
						var tcpAddr *net.TCPAddr
						var err error
						if ipv6Enable {
							if ipv4Enable {
								tcpAddr, err = net.ResolveTCPAddr("tcp", keys[1])
							} else {
								tcpAddr, err = net.ResolveTCPAddr("tcp6", keys[1])
							}
						} else {
							tcpAddr, err = net.ResolveTCPAddr("tcp4", keys[1])
						}
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						DNS = tcpAddr.String()
						IPMap[tcpAddr.IP.String()] = IPConfig{option, minTTL, maxTTL, syncMSS}
						logPrintln(2, string(line))
					} else if keys[0] == "dns64" {
						DNS64 = keys[1]
						logPrintln(2, string(line))
					} else if keys[0] == "ipv6" {
						if keys[1] == "true" {
							ipv6Enable = true
						} else {
							ipv6Enable = false
						}
						logPrintln(2, string(line))
					} else if keys[0] == "ipv4" {
						if keys[1] == "true" {
							ipv4Enable = true
						} else {
							ipv4Enable = false
						}
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
					} else if keys[0] == "tcpfastopen" || keys[0] == "tfo" {
						if keys[1] == "true" {
							option |= OPT_TFO
							TFOEnable = true
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
					} else if keys[0] == "seq" {
						if keys[1] == "true" {
							option |= OPT_SEQ
						} else {
							option &= ^uint32(OPT_SEQ)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "noflag" {
						if keys[1] == "true" {
							option |= OPT_NOFLAG
						} else {
							option &= ^uint32(OPT_NOFLAG)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "https" {
						if keys[1] == "true" {
							option |= OPT_HTTPS
						} else {
							option &= ^uint32(OPT_HTTPS)
						}
						logPrintln(2, string(line))
					} else if keys[0] == "quic" {
						if keys[1] == "true" {
							option |= OPT_QUIC
						} else {
							option &= ^uint32(OPT_QUIC)
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
					} else if keys[0] == "subdomain" {
						SubdomainDepth, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
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
									DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS, 0, -1, nil, prefix}
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

								if ipv4Enable && count4 == 0 {
									count4 = -1
								}
								if ipv6Enable && count6 == 0 {
									count6 = -1
								}

								DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS, int16(count4), int16(count6), answer4, answer6}
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
						ipv6Enable = true
						logPrintln(2, string(line))
					} else if keys[0] == "ipv4" {
						ipv4Enable = true
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
							if strings.Index(keys[0], "/") > 0 {
								_, ipnet, err := net.ParseCIDR(keys[0])
								if err == nil {
									IPMap[ipnet.String()] = IPConfig{option, minTTL, maxTTL, syncMSS}
									IPBlock = true
								}
							} else {
								var count4 int16
								var count6 int16
								if ipv4Enable {
									count4 = -1
								} else {
									count4 = 0
								}
								if ipv6Enable {
									count6 = -1
								} else {
									count6 = 0
								}

								ip := net.ParseIP(keys[0])

								if ip != nil {
									IPMap[keys[0]] = IPConfig{option, minTTL, maxTTL, syncMSS}
								} else {
									DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS, count4, count6, nil, nil}
								}
							}
						}
					}
				}
			}
		}
	}

	if TFOEnable {
		CookiesMap = make(map[string][]byte)
	}

	return nil
}

func Wait() {
	wg.Wait()
}
