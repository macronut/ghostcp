// +build !windows

package tcpioneer

import (
	"encoding/binary"
	"log"
	"net"
)

func DNSDaemon() {
	wg.Add(1)
	defer wg.Done()

	laddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
	listener, err := net.ListenUDP("udp", laddr)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err)
		}
		return
	}
	defer listener.Close()

	buf := make([]byte, 1500)
	for {
		n, addr, err := listener.ReadFromUDP(buf)
		if err != nil {
			if LogLevel > 0 {
				log.Println(err)
			}
			continue
		}

		qname, qtype, off := getQName(buf[:])
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
				buf[2] = 0x81
				buf[3] = 0x80
				binary.BigEndian.PutUint16(buf[6:], 0)

				_, err = listener.WriteToUDP(buf[:n], addr)
			} else {
				if anCount > 0 {
					logPrintln(qname)

					buf[2] = 0x81
					buf[3] = 0x80
					binary.BigEndian.PutUint16(buf[6:], anCount)
					copy(buf[n:], answers)
					n += len(answers)

					_, err = listener.WriteToUDP(buf[:n], addr)
				} else {
					logPrintln(qname, config.Option)
					go func(level int, answers6 []byte, offset int, addr net.UDPAddr) {
						request := make([]byte, n)
						copy(request, buf[:n])

						var response []byte
						var err error
						if qtype != 28 || answers6 == nil {
							response, err = TCPlookup(request[:], DNS)
						} else {
							if DNS64 == "" {
								response, err = TCPlookupDNS64(buf[:], DNS, offset, answers6)
							} else {
								response, err = TCPlookup(buf[:], DNS64)
							}
						}
						if err != nil {
							if LogLevel > 0 {
								log.Println(err)
							}
							return
						}
						if off >= len(response) {
							return
						}

						count := int(binary.BigEndian.Uint16(response[6:8]))

						ips := getAnswers(response[off:], count)
						for _, ip := range ips {
							ipConfig, ok := IPMap[ip]
							option := ipConfig.Option | config.Option
							if ok == false {
								IPMap[ip] = IPConfig{option, config.TTL, config.MAXTTL, config.MSS}
							}
						}

						_, err = listener.WriteToUDP(response, &addr)
					}(int(config.Option), config.Answers6, off, *addr)
				}
			}
		} else {
		}
	}
}

func DNSRecvDaemon() {
}

func UDPDaemon(dstPort int, forward bool) {
}
