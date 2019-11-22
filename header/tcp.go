package tcpioneer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/williamfhe/godivert"
)

type ConnInfo struct {
	Option uint32
	SeqNum uint32
	TTL    byte
	MAXTTL byte
}

var PortList4 [65536]*ConnInfo
var PortList6 [65536]*ConnInfo
var CookiesMap map[string][]byte

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

func TFORecv(srcPort int, forward bool) {
	if TFOEnable == false {
		return
	}

	var filter string
	var layer uint8
	if forward {
		filter = fmt.Sprintf("tcp.SrcPort == %d and tcp.Syn", srcPort)
		layer = 1
	} else {
		filter = fmt.Sprintf("inbound and tcp.SrcPort == %d and tcp.Syn", srcPort)
		layer = 0
	}
	winDivert, err := godivert.NewWinDivertHandleWithLayer(filter, layer)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err, filter)
		}
		return
	}

	go func() {
		defer winDivert.Close()

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

			if forward && !ipv6 {
				lanAddr := [4]byte{192, 168, 137, 0}
				if bytes.Compare(packet.Raw[16:19], lanAddr[:3]) == 0 {
					_, err = winDivert.Send(packet)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
					}
					continue
				}
			}

			dstPort := binary.BigEndian.Uint16(packet.Raw[ipheadlen+2:])

			if packet.Raw[ipheadlen+13] == TCP_SYN|TCP_ACK {
				var info *ConnInfo
				if ipv6 {
					info = PortList6[dstPort]
				} else {
					info = PortList4[dstPort]
				}

				if info != nil && info.Option&OPT_TFO != 0 {
					ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:]) - 3
					tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4

					optStart := ipheadlen + 20
					option := packet.Raw[optStart : ipheadlen+tcpheadlen]
					cookies := getCookies(option)
					if cookies != nil {
						tmp_cookies := make([]byte, len(cookies))
						copy(tmp_cookies, cookies)
						CookiesMap[packet.SrcIP().String()] = tmp_cookies
						continue
					} else {
						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], ackNum)
						packet.CalcNewChecksum(winDivert)
					}
				}
			}

			_, err = winDivert.Send(packet)
			if err != nil {
				if LogLevel > 0 {
					log.Println(err)
				}
			}
		}
	}()
}

func TCPDaemon(address string, forward bool) {
	wg.Add(1)

	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		if LogLevel > 0 {
			log.Println(err)
		}
		return
	}

	var filter string
	var layer uint8
	if forward {
		if address[0] == ':' {
			filter = fmt.Sprintf("tcp.DstPort == %s", address[1:])
		} else {
			filter = fmt.Sprintf("ip.DstAddr = %s and tcp.DstPort == %d", tcpAddr.IP.String(), tcpAddr.Port)
		}
		layer = 1
	} else {
		if address[0] == ':' {
			filter = fmt.Sprintf("outbound and tcp.DstPort == %s", address[1:])
		} else {
			filter = fmt.Sprintf("outbound and ip.DstAddr = %s and tcp.DstPort == %d", tcpAddr.IP.String(), tcpAddr.Port)
		}
		layer = 0
	}

	winDivert, err := godivert.NewWinDivertHandleWithLayer(filter, layer)
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

			if forward && !ipv6 {
				lanAddr := [4]byte{192, 168, 137, 0}
				if bytes.Compare(packet.Raw[12:15], lanAddr[:3]) == 0 {
					_, err = winDivert.Send(packet)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
					}
					continue
				}
			}

			srcPort := int(binary.BigEndian.Uint16(packet.Raw[ipheadlen:]))

			if (packet.Raw[ipheadlen+13] & TCP_ACK) != 0 {
				var info *ConnInfo
				if ipv6 {
					info = PortList6[srcPort]
				} else {
					info = PortList4[srcPort]
				}

				if info == nil || info.Option == 0 {
					_, err = winDivert.Send(packet)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
					}
					continue
				}

				tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
				dstPort := int(binary.BigEndian.Uint16(packet.Raw[ipheadlen+2:]))

				payloadLen := int(packet.PacketLen) - ipheadlen - tcpheadlen

				host_offset := 0
				host_length := 0
				switch dstPort {
				case 53:
					if payloadLen > 0 {
						if len(packet.Raw[ipheadlen+tcpheadlen:]) > 21 {
							host_offset = 20
							host_length = 1
						}
						if ipv6 {
							PortList6[srcPort] = nil
						} else {
							PortList4[srcPort] = nil
						}
					}
				case 80:
					request := packet.Raw[ipheadlen+tcpheadlen:]

					if info.Option&OPT_HTTPS != 0 {
						if payloadLen == 0 {
							continue
						}
						host_offset, host_length = getHost(request)

						resStart := bytes.Index(request, []byte(" "))
						if resStart == -1 {
							continue
						}
						resStart++
						resLen := bytes.Index(request[resStart:], []byte(" "))
						if resLen == -1 {
							continue
						}
						seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])

						copy(rawbuf, packet.Raw)
						head := []byte("HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\nContent-Length: 0\r\nLocation: https://")
						offset := ipheadlen + 20
						copy(rawbuf[offset:], head)
						offset += len(head)
						copy(rawbuf[offset:], request[host_offset:host_offset+host_length])
						offset += host_length
						copy(rawbuf[offset:], request[resStart:resStart+resLen])
						offset += resLen
						copy(rawbuf[offset:], []byte("\r\n\r\n"))
						offset += 4

						packet.PacketLen = uint(offset)

						if ipv6 {
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(int(packet.PacketLen)-ipheadlen))
							copy(rawbuf[8:], packet.Raw[24:40])
							copy(rawbuf[24:], packet.Raw[8:24])
						} else {
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
							copy(rawbuf[12:], packet.Raw[16:20])
							copy(rawbuf[16:], packet.Raw[12:16])
						}
						copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
						copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
						rawbuf[ipheadlen+12] = 5 << 4

						binary.BigEndian.PutUint32(rawbuf[ipheadlen+4:], 1)
						binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], seqNum+uint32(payloadLen))

						rawbuf[ipheadlen+13] = TCP_PSH | TCP_ACK
						packet.Raw = rawbuf[:packet.PacketLen]
						packet.Addr.Data |= 0x1

						packet.CalcNewChecksum(winDivert)

						_, err = winDivert.Send(packet)
						if err != nil {
							if LogLevel > 0 {
								log.Println(err)
							}
						}

						rst_packet := *packet
						rst_packet.PacketLen = uint(ipheadlen + 20)
						if ipv6 {
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(int(rst_packet.PacketLen)-ipheadlen))
						} else {
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(rst_packet.PacketLen))
						}
						rawbuf[ipheadlen+13] = TCP_RST
						binary.BigEndian.PutUint32(rawbuf[ipheadlen+4:], uint32(offset+1))
						binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], 0)

						rst_packet.Raw = rawbuf[:ipheadlen+20]
						packet.Addr.Data |= 0x1
						rst_packet.CalcNewChecksum(winDivert)
						_, err = winDivert.Send(&rst_packet)
						if err != nil {
							if LogLevel > 0 {
								log.Println(err)
							}
						}

						continue
					} else if payloadLen > 0 {
						host_offset, host_length = getHost(request)
					}
				case 443:
					seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
					if seqNum == info.SeqNum+1 {
						if info.Option&OPT_TFO != 0 {
							if payloadLen > 3 {
								packet.Raw[ipheadlen+tcpheadlen] = 0xFF
								packet.Raw[ipheadlen+tcpheadlen+1] = 0xFF
								packet.Raw[ipheadlen+tcpheadlen+2] = 0xFF
							} else {
								seqNum += 3
								binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], seqNum)
							}

							packet.CalcNewChecksum(winDivert)
						} else if payloadLen > 0 {
							if info.Option&OPT_SYN != 0 {
								packet.Raw[ipheadlen+13] = TCP_SYN
								seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
								binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], seqNum-1)
								binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], 0)
								packet.CalcNewChecksum(winDivert)
							} else {
								hello := packet.Raw[ipheadlen+tcpheadlen:]
								host_offset, host_length = getSNI(hello)
							}
						}
					} else {
						if ipv6 {
							PortList6[srcPort] = nil
						} else {
							PortList4[srcPort] = nil
						}
					}
				default:
					host_length = payloadLen
				}

				if host_length == 0 {
					_, err = winDivert.Send(packet)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
					}
					continue
				}

				fake_packet := *packet
				copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])

				if info.TTL > 0 {
					if ipv6 {
						rawbuf[7] = byte(info.TTL)
					} else {
						rawbuf[8] = byte(info.TTL)
					}
				}

				fakeipheadlen := ipheadlen
				if (info.Option & OPT_IPOPT) != 0 {
					fakeipheadlen += 32
					copy(rawbuf[fakeipheadlen:], packet.Raw[ipheadlen:ipheadlen+tcpheadlen])
					if ipv6 {
					} else {
						rawbuf[0] = rawbuf[0]&0xF0 | byte(fakeipheadlen/4)
					}
					for i := 0; i < 31; i++ {
						rawbuf[ipheadlen+i] = 1
					}
					rawbuf[ipheadlen+31] = 0
				}

				if (info.Option & OPT_MD5) != 0 {
					copy(rawbuf[fakeipheadlen+20:], []byte{19, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
					rawbuf[fakeipheadlen+12] = 10 << 4
				}

				if (info.Option & OPT_ACK) != 0 {
					ackNum := binary.BigEndian.Uint32(rawbuf[fakeipheadlen+8:])
					ackNum += uint32(binary.BigEndian.Uint16(rawbuf[fakeipheadlen+14:]))
					binary.BigEndian.PutUint32(rawbuf[fakeipheadlen+8:], ackNum)
				}

				if (info.Option & OPT_BAD) != 0 {
					rawbuf[fakeipheadlen+12] = 4 << 4
				}

				if (info.Option & OPT_SEQ) != 0 {
					rawbuf[fakeipheadlen+13] = TCP_SYN

					seqNum := binary.BigEndian.Uint32(rawbuf[ipheadlen+4:])
					seqNum += 65536
					binary.BigEndian.PutUint32(rawbuf[fakeipheadlen+4:], seqNum)
					binary.BigEndian.PutUint32(rawbuf[fakeipheadlen+8:], 0)
				}

				fake_packet.Raw = rawbuf[:len(packet.Raw)]
				fake_packet.CalcNewChecksum(winDivert)

				if (info.Option & OPT_CSUM) != 0 {
					binary.BigEndian.PutUint16(rawbuf[fakeipheadlen+16:], 0)
				}

				if (info.Option & (OPT_ACK | OPT_SEQ)) == 0 {
					_, err = winDivert.Send(&fake_packet)
					if err != nil {
						if LogLevel > 0 {
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
					if LogLevel > 0 {
						log.Println(err)
					}
					continue
				}

				if (info.Option & OPT_ACK) != 0 {
					_, err = winDivert.Send(&fake_packet)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
						continue
					}
					time.Sleep(time.Microsecond * 8)
				}

				_, err = winDivert.Send(&fake_packet)
				if err != nil {
					if LogLevel > 0 {
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
					if LogLevel > 0 {
						log.Println(err)
					}
					continue
				}
			} else if packet.Raw[ipheadlen+13] == TCP_SYN {
				dstAddr := packet.DstIP().String()
				config, ok := IPLookup(dstAddr)

				if ok && config.Option != 0 {
					seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
					if ipv6 {
						PortList6[srcPort] = &ConnInfo{config.Option, seqNum, config.TTL, config.MAXTTL}
					} else {
						PortList4[srcPort] = &ConnInfo{config.Option, seqNum, config.TTL, config.MAXTTL}
					}

					tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4

					if config.Option&OPT_HTTPS != 0 {
						if tcpAddr.Port == 80 {
							copy(rawbuf, packet.Raw)
							binary.BigEndian.PutUint32(rawbuf[ipheadlen+4:], 0)
							binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], seqNum+1)
							rawbuf[ipheadlen+13] = TCP_SYN | TCP_ACK

							packet.PacketLen = uint(ipheadlen + 32)
							if ipv6 {
								binary.BigEndian.PutUint16(rawbuf[4:], uint16(int(packet.PacketLen)-ipheadlen))
								copy(rawbuf[8:], packet.Raw[24:40])
								copy(rawbuf[24:], packet.Raw[8:24])
							} else {
								binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
								copy(rawbuf[12:], packet.Raw[16:20])
								copy(rawbuf[16:], packet.Raw[12:16])
							}
							copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
							copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
							copy(rawbuf[ipheadlen+20:], []byte{0x02, 0x04, 0x05, 0xa8, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03, 0x03, 0x09})
							rawbuf[ipheadlen+12] = 8 << 4
							packet.Addr.Data |= 0x1
							packet.Raw = rawbuf[:ipheadlen+32]

							packet.CalcNewChecksum(winDivert)
							_, err = winDivert.Send(packet)
							if err != nil {
								if LogLevel > 0 {
									log.Println(err)
								}
							}
							continue
						}
					}

					if config.Option&OPT_TFO != 0 {
						synOption := make([]byte, tcpheadlen-20)
						copy(synOption, packet.Raw[ipheadlen+20:])

						copy(rawbuf, packet.Raw)
						cookies, _ := CookiesMap[dstAddr]

						if cookies != nil {
							cookiesLen := len(cookies)
							optLen := cookiesLen + 2
							offset := byte((optLen + 3) / 4)
							rawbuf[ipheadlen+12] += offset << 4
							rawbuf[int(packet.PacketLen)] = 34
							rawbuf[int(packet.PacketLen)+1] = byte(optLen)
							copy(rawbuf[int(packet.PacketLen)+2:], cookies)
							packet.PacketLen += uint(offset * 4)

							rawbuf[packet.PacketLen] = 0x16
							rawbuf[packet.PacketLen+1] = 0x03
							rawbuf[packet.PacketLen+2] = 0x01
							packet.PacketLen += 3
						} else {
							packet.PacketLen += 4
							rawbuf[ipheadlen+12] += 1 << 4
							rawbuf[ipheadlen+tcpheadlen] = 34
							rawbuf[ipheadlen+tcpheadlen+1] = 2
							rawbuf[ipheadlen+tcpheadlen+2] = 1
							rawbuf[ipheadlen+tcpheadlen+3] = 1
						}

						if ipv6 {
							PortList6[srcPort].SeqNum = seqNum
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(int(packet.PacketLen)-ipheadlen))
						} else {
							PortList4[srcPort].SeqNum = seqNum
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
						}

						packet.Raw = rawbuf[:packet.PacketLen]

						packet.CalcNewChecksum(winDivert)
					}

					if (config.Option & OPT_MSS) != 0 {
						if tcpheadlen >= 24 {
							tcpOption := packet.Raw[ipheadlen+20]
							if tcpOption == 2 {
								binary.BigEndian.PutUint16(packet.Raw[ipheadlen+22:], config.MSS)
								packet.CalcNewChecksum(winDivert)
							}
						}
					}

					logPrintln(2, packet.DstIP(), config.Option)
				} else {
					if ipv6 {
						PortList6[srcPort] = nil
					} else {
						PortList4[srcPort] = nil
					}
					logPrintln(3, packet.DstIP())
				}

				_, err = winDivert.Send(packet)
				if err != nil {
					if LogLevel > 0 {
						log.Println(err)
					}
				}
			} else {
				_, err = winDivert.Send(packet)
				if err != nil {
					if LogLevel > 0 {
						log.Println(err)
					}
				}
			}
		}
	}()
}

func NAT64(ipv6 net.IP, ipv4 net.IP, forward bool) {
	wg.Add(1)
	defer wg.Done()

	copy(ipv6[12:], ipv4[:4])
	var filter string
	var layer uint8
	if forward {
		filter = "!loopback and ((ip.DstAddr=" + ipv4.String() + ") or (ipv6.SrcAddr=" + ipv6.String() + "))"
		layer = 1
	} else {
		filter = "!loopback and ((outbound and ip.DstAddr=" + ipv4.String() + ") or (inbound and ipv6.SrcAddr=" + ipv6.String() + "))"
		layer = 0
	}

	winDivert, err := godivert.NewWinDivertHandleWithLayer(filter, layer)
	if err != nil {
		if LogLevel > 0 {
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
			if LogLevel > 0 {
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
			if LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}
}
