package tcpioneer

import (
	"encoding/binary"
	"log"
	"os/exec"
	"strconv"

	"github.com/williamfhe/godivert"
)

func DNSDaemon() {
	wg.Add(1)
	defer wg.Done()

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
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err, filter)
		}
		return
	}
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
					logPrintln(2, qname)
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
				} else {
					logPrintln(3, qname)
				}
			}
		} else {
			_, err = winDivert.Send(packet)
		}
	}
}

func DNSRecvDaemon() {
	wg.Add(1)
	defer wg.Done()

	filter := "((outbound and loopback) or inbound) and udp.SrcPort == 53"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

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

		config := domainLookup(qname)

		if config.Option > 1 && qtype == 1 {
			logPrintln(2, qname, "LEVEL", config.Option)
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

func UDPDaemon(dstPort int, forward bool) {
	wg.Add(1)
	defer wg.Done()

	var filter string
	var layer uint8
	if forward {
		filter = "!loopback and udp.DstPort == " + strconv.Itoa(dstPort)
		layer = 1
	} else {
		filter = "outbound and !loopback and udp.DstPort == " + strconv.Itoa(dstPort)
		layer = 0
	}

	winDivert, err := godivert.NewWinDivertHandleWithLayerFlags(filter, layer, 0)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err, filter)
		}
		return
	}
	defer winDivert.Close()

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			if LogLevel > 0 {
				log.Println(err)
			}
			return
		}

		_, ok := IPMap[packet.DstIP().String()]
		if !ok {
			_, err = winDivert.Send(packet)
			if err != nil {
				if LogLevel > 0 {
					log.Println(err)
				}
				return
			}
		}
	}
}
