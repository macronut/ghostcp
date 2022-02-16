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
	ECS      net.IP
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

var DefaultConfig *Config = nil
var DomainMap map[string]Config
var IPMap map[string]IPConfig
var BadIPMap map[string]bool
var wg sync.WaitGroup
var mutex sync.Mutex

var SubdomainDepth = 2
var LogLevel = 0
var Forward bool = false
var IPBlock = false
var IPMode = false
var TFOEnable = false
var RSTFilterEnable = false
var DetectEnable = false

var ScanURL string = ""
var ScanTimeout uint = 0

const (
	OPT_NONE  = 0x0
	OPT_TTL   = 0x1 << 0
	OPT_MD5   = 0x1 << 1
	OPT_WMD5  = 0x1 << 2
	OPT_WACK  = 0x1 << 3
	OPT_WCSUM = 0x1 << 4
	OPT_BAD   = 0x1 << 5
	OPT_IPOPT = 0x1 << 6
	OPT_SEQ   = 0x1 << 7
	OPT_HTTPS = 0x1 << 8
	OPT_MSS   = 0x1 << 9
	OPT_WTFO  = 0x1 << 10
	OPT_WULEN = 0x1 << 11

	OPT_MODE2  = 0x10000 << 0
	OPT_DF     = 0x10000 << 1
	OPT_TFO    = 0x10000 << 2
	OPT_SYN    = 0x10000 << 3
	OPT_NOFLAG = 0x10000 << 4
	OPT_SSEG   = 0x10000 << 5
	OPT_QUIC   = 0x10000 << 6
	OPT_FILTER = 0x10000 << 7
	OPT_SAT    = 0x10000 << 8
	OPT_NORST  = 0x10000 << 9
)

var MethodMap = map[string]uint32{
	"none":   OPT_NONE,
	"ttl":    OPT_TTL,
	"mss":    OPT_MSS,
	"md5":    OPT_MD5,
	"w-md5":  OPT_WMD5,
	"w-ack":  OPT_WACK,
	"w-csum": OPT_WCSUM,
	"bad":    OPT_BAD,
	"ipopt":  OPT_IPOPT,
	"seq":    OPT_SEQ,
	"https":  OPT_HTTPS,
	"w-tfo":  OPT_WTFO,
	"w-ulen": OPT_WULEN,

	"mode2":   OPT_MODE2,
	"df":      OPT_DF,
	"tfo":     OPT_TFO,
	"syn":     OPT_SYN,
	"no-flag": OPT_NOFLAG,
	"s-seg":   OPT_SSEG,
	"quic":    OPT_QUIC,
	"filter":  OPT_FILTER,
	"sat":     OPT_SAT,
	"no-rst":  OPT_NORST,
}

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
		return Config{0, 0, 0, 0, nil, 0, 0, nil, nil}, true
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

	if DefaultConfig != nil {
		return *DefaultConfig, true
	} else {
		return Config{0, 0, 0, 0, nil, -1, -1, nil, nil}, false
	}
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

func getSNIFromQUIC(payload []byte) string {
	flags := payload[0]
	longHead := flags&0x80 != 0
	if !longHead {
		return ""
	}
	fixBit := flags&0x40 != 0
	if !fixBit {
		return ""
	}
	packetType := flags & 0x30 >> 4
	if packetType != 0 {
		return ""
	}

	version := string(payload[1:5])
	if version != "Q046" {
		return ""
	}

	dcil := (payload[5] & 0xF0) >> 4
	scil := payload[5] & 0x0F

	dstIDLen := 0
	if dcil > 0 {
		dstIDLen = int(dcil + 3)
	}
	srcIDLen := 0
	if scil > 0 {
		srcIDLen = int(scil + 3)
	}

	headlen := 6 + dstIDLen + srcIDLen
	hs := payload[headlen:]

	offset := bytes.Index(hs, []byte("CHLO"))
	if offset > 0 {
		hs = hs[offset:]
		tagNum := int(binary.LittleEndian.Uint16(hs[4:8]))
		hs = hs[8:]
		tagsOffset := 0
		for i := 0; i < tagNum; i++ {
			if string(hs[i*8:i*8+4]) == "SNI\x00" {
				tagsOffsetEnd := int(binary.LittleEndian.Uint16(hs[i*8+4 : i*8+8]))
				return string(hs[tagNum*8+tagsOffset : tagNum*8+tagsOffsetEnd])
			}
			tagsOffset = int(binary.LittleEndian.Uint16(hs[i*8+4 : i*8+8]))
		}
	}

	return ""
}

func getMyIPv4() net.IP {
	s, err := net.InterfaceAddrs()
	if err != nil {
		log.Println(err)
		return nil
	}
	for _, a := range s {
		ip, ipNet, err := net.ParseCIDR(a.String())
		if err != nil {
			log.Println(err)
			return nil
		}
		myIP := ip
		gateway := ip.Mask(ipNet.Mask)
		if gateway.Equal(net.IPv4(169, 254, 0, 0)) {
			continue
		}

		gateway[len(gateway)-1] += 1
		if myIP.Equal(gateway) {
			continue
		}

		ip4 := myIP.To4()
		if ip4 != nil {
			return ip4
		}
	}
	return nil
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
	BadIPMap = make(map[string]bool)

	conf, err := os.Open("default.conf")
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
	var ecs net.IP = nil

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if len(line) > 0 {
			if line[0] != '#' {
				l := strings.SplitN(string(line), "#", 2)[0]
				keys := strings.SplitN(l, "=", 2)
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
					} else if keys[0] == "ecs" {
						ecs = net.ParseIP(keys[1])
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
					} else if keys[0] == "method" {
						option = OPT_NONE
						methods := strings.Split(keys[1], ",")
						for _, m := range methods {
							method, ok := MethodMap[m]
							if ok {
								option |= method
								switch method {
								case OPT_TFO:
									TFOEnable = true
								case OPT_FILTER:
									DetectEnable = true
								case OPT_NORST:
									RSTFilterEnable = true
								}
							} else {
								logPrintln(1, "Unsupported method: "+m)
							}
						}
						logPrintln(2, string(line))
					} else if keys[0] == "ttl" {
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						minTTL = byte(ttl)
						logPrintln(2, string(line))
					} else if keys[0] == "mss" {
						mss, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						syncMSS = uint16(mss)
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
						} else {
							logPrintln(1, string(line))
						}
					} else {
						ip := net.ParseIP(keys[0])
						if ip == nil {
							if strings.HasSuffix(keys[1], ":") {
								prefix := net.ParseIP(keys[1])
								if prefix != nil {
									DomainMap[keys[0]] = Config{option, minTTL, maxTTL, syncMSS, ecs, 0, -1, nil, prefix}
								}
							} else {
								if strings.HasPrefix(keys[1], "[") {
									var ok bool
									config, ok := DomainMap[keys[1][1:len(keys[1])-1]]
									if !ok {
										log.Println(string(line), "bad domain")
									}
									DomainMap[keys[0]] = config
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

									DomainMap[keys[0]] = Config{option,
										minTTL, maxTTL, syncMSS, ecs,
										int16(count4), int16(count6),
										answer4, answer6}
								}
							}
						} else {
							prefix := net.ParseIP(keys[1])
							ip4 := ip.To4()
							if ip4 != nil {
								if Forward {
									go NAT64(ip4, prefix, true)
								}
								go NAT64(ip4, prefix, false)
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
								ip := net.ParseIP(keys[0])
								if ip != nil {
									IPMap[keys[0]] = IPConfig{option, minTTL, maxTTL, syncMSS}
								} else {
									var count4 int16 = 0
									var count6 int16 = 0
									if ipv4Enable {
										count4 = -1
									}
									if ipv6Enable {
										count6 = -1
									}
									if keys[0] == "*" {
										DefaultConfig = &Config{
											option, minTTL, maxTTL, syncMSS, ecs,
											count4, count6, nil, nil}
									} else {
										DomainMap[keys[0]] = Config{
											option, minTTL, maxTTL, syncMSS, ecs,
											count4, count6, nil, nil}
									}
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

func LoadHosts(name string) error {
	hosts, err := os.Open(name)
	if err != nil {
		return err
	}
	defer hosts.Close()

	br := bufio.NewReader(hosts)

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			logPrintln(1, err)
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		keys := strings.Fields(string(line))
		if len(keys) == 2 {
			ip := keys[0]
			config, ok := DomainMap[keys[1]]
			if ok {
				IPMap[ip] = IPConfig{config.Option, config.TTL, config.MAXTTL, config.MSS}
			}
		}
	}

	return nil
}

func Wait() {
	wg.Wait()
}
