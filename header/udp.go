package tcpioneer

import (
	"encoding/binary"
	"log"
	"os/exec"
	"strconv"

	"github.com/macronut/godivert"
)

func DNSDaemon() {
	wg.Add(1)

	arg := []string{"/flushdns"}
	cmd := exec.Command("ipconfig", arg...)
	d, err := cmd.CombinedOutput()
	if err != nil {
		if LogLevel > 0 {
			log.Println(string(d), err)
		}
		return
	}

	filter := "outbound and udp.DstPort == 53"
	mutex.Lock()
	winDivert, err := godivert.NewWinDivertHandle(filter)
	mutex.Unlock()
	if err != nil {
		if LogLevel > 0 {
			log.Println(err, filter)
		}
		return
	}

	go func() {
		defer wg.Done()
		defer winDivert.Close()

		rawbuf := make([]byte, 1500)
		for {
			packet, err := winDivert.Recv()
			if err != nil {
				if LogLevel > 0 {
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
				logPrintln(2, "DNS Segmentation fault")
				continue
			}

			config, ok := domainLookup(qname)
			if ok {
				var anCount int16 = 0
				var answers []byte = nil

				if qtype == 1 {
					answers = config.Answers4
					anCount = config.ANCount4
				} else if qtype == 28 {
					answers = config.Answers6
					anCount = config.ANCount6
				}

				if anCount == 0 {
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
				} else if anCount > 0 {
					logPrintln(2, qname, qtype)
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
					binary.BigEndian.PutUint16(rawbuf[ipheadlen+14:], uint16(anCount))
					copy(rawbuf[ipheadlen+8+len(request):], answers)

					packet.PacketLen = uint(packetsize)
					packet.Raw = rawbuf[:packetsize]
					packet.CalcNewChecksum(winDivert)

					_, err = winDivert.Send(packet)
				} else {
					logPrintln(2, qname, config.Option)
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

						request := packet.Raw[ipheadlen+udpheadlen:]

						if config.ECS != nil {
							request = AddECS(request, config.ECS)
						}

						var response []byte
						var err error
						if qtype == 28 && answers6 != nil {
							response, err = TCPlookupDNS64(request, DNS, offset, answers6)
						} else {
							response, err = TCPlookup(request, DNS)
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

						//Filter
						if config.Option&OPT_FILTER != 0 {
							if qtype == 28 && ipv6 {
								ips = TCPDetection(winDivert, *packet.Addr, rawbuf[24:40], ips, 443, int(config.TTL))
							} else if qtype == 1 && !ipv6 {
								ips = TCPDetection(winDivert, *packet.Addr, rawbuf[16:20], ips, 443, int(config.TTL))
							} else {
								ips = TCPDetection(winDivert, *packet.Addr, nil, ips, 443, int(config.TTL))
							}
							count, ans := packAnswers(ips, qtype)
							binary.BigEndian.PutUint16(response[6:8], uint16(count))
							binary.BigEndian.PutUint16(response[10:12], 0)
							copy(response[off:], ans)
							response = response[:off+len(ans)]
						}

						for _, ip := range ips {
							_, ok := IPLookup(ip)
							if IPBlock && !ok {
								var ipconfig IPConfig
								ipconfig, ok = IPBlockLookup(ip)
								if ok {
									logPrintln(3, ip, ipconfig.Option)
									IPMap[ip] = ipconfig
								}
							}
							if !ok {
								logPrintln(3, ip, config.Option)
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
			} else {
				logPrintln(3, qname)
				_, err = winDivert.Send(packet)
			}
		}
	}()
}

func DNSRecvDaemon() {
	wg.Add(1)

	filter := "udp.SrcPort == 53"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err, filter)
		}
		return
	}

	go func() {
		defer wg.Done()
		defer winDivert.Close()
		rawbuf := make([]byte, 1500)
		for {
			packet, err := winDivert.Recv()
			if err != nil {
				if LogLevel > 0 {
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
				logPrintln(2, "DNS Segmentation fault")
				continue
			}

			config, ok := domainLookup(qname)

			if ok {
				var anCount int16 = 0
				var answers []byte = nil

				if qtype == 1 {
					answers = config.Answers4
					anCount = config.ANCount4
				} else if qtype == 28 {
					answers = config.Answers6
					anCount = config.ANCount6
				}

				if anCount == 0 {
					logPrintln(3, qname, qtype, "NoRecord")

					udpsize := udpheadlen + off
					packetsize := ipheadlen + udpsize
					binary.BigEndian.PutUint16(packet.Raw[ipheadlen+14:], 0)
					binary.BigEndian.PutUint16(packet.Raw[ipheadlen+4:], uint16(udpsize))
					if ipv6 {
						binary.BigEndian.PutUint16(packet.Raw[4:], uint16(packetsize-ipheadlen))
					} else {
						binary.BigEndian.PutUint16(packet.Raw[2:], uint16(packetsize))
					}
					packet.Raw = packet.Raw[:packetsize]

					packet.PacketLen = uint(packetsize)
					packet.CalcNewChecksum(winDivert)
				} else if anCount > 0 {
					logPrintln(2, qname, qtype)
					copy(rawbuf, packet.Raw[:ipheadlen+udpheadlen+off])
					binary.BigEndian.PutUint16(rawbuf[ipheadlen+14:], uint16(anCount))
					copy(rawbuf[ipheadlen+udpheadlen+off:], answers)

					udpsize := udpheadlen + off + len(answers)
					packetsize := ipheadlen + udpsize
					binary.BigEndian.PutUint16(rawbuf[ipheadlen+4:], uint16(udpsize))
					if ipv6 {
						binary.BigEndian.PutUint16(rawbuf[4:], uint16(packetsize-ipheadlen))
					} else {
						binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
					}

					packet.PacketLen = uint(packetsize)
					packet.Raw = rawbuf[:packetsize]
					packet.CalcNewChecksum(winDivert)
				} else if config.Option > 1 {
					logPrintln(2, qname, config.Option)
					response := packet.Raw[ipheadlen+udpheadlen:]
					count := int(binary.BigEndian.Uint16(response[6:8]))
					ips := getAnswers(response[off:], count)

					for _, ip := range ips {
						_, ok := IPLookup(ip)
						if IPBlock && !ok {
							var ipconfig IPConfig
							ipconfig, ok = IPBlockLookup(ip)
							if ok {
								logPrintln(3, ip, ipconfig.Option)
								IPMap[ip] = ipconfig
							}
						}
						if !ok {
							logPrintln(3, ip, config.Option)
							IPMap[ip] = IPConfig{config.Option, config.TTL, config.MAXTTL, config.MSS}
						}
					}
				}
			}

			_, err = winDivert.Send(packet)
		}
	}()
}

func UDPDaemon(dstPort int, forward bool) {
	wg.Add(1)

	var filter string
	var layer uint8
	if forward {
		filter = "udp.DstPort == " + strconv.Itoa(dstPort)
		layer = 1
	} else {
		filter = "outbound and udp.DstPort == " + strconv.Itoa(dstPort)
		layer = 0
	}

	winDivert, err := godivert.WinDivertOpen(filter, layer, 1, 0)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err, filter)
		}
		return
	}

	go func() {
		defer wg.Done()
		defer winDivert.Close()

		for {
			packet, err := winDivert.Recv()
			if err != nil {
				if LogLevel > 0 {
					log.Println(err)
				}
				continue
			}

			config, ok := IPLookup(packet.DstIP().String())
			if ok {
				if config.Option == 0 || (config.Option&OPT_QUIC != 0) {
					if config.Option&OPT_WULEN != 0 {
						ipv6 := packet.Raw[0]>>4 == 6
						var ipheadlen int
						if ipv6 {
							ipheadlen = 40
						} else {
							ipheadlen = int(packet.Raw[0]&0xF) * 4
						}
						//ulen := binary.BigEndian.Uint16(packet.Raw[ipheadlen+udpheadlen:])
						binary.BigEndian.PutUint16(packet.Raw[ipheadlen+4:], 0)
						packet.CalcNewChecksum(winDivert)
					}
					_, err = winDivert.Send(packet)
				}
			} else {
				_, err = winDivert.Send(packet)
			}
			if err != nil {
				if LogLevel > 0 {
					log.Println(err)
				}
				continue
			}
		}
	}()
}
