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
	AckNum uint32
	TTL    byte
	MAXTTL byte
}

var PortList4 [65536]*ConnInfo
var PortList6 [65536]*ConnInfo
var OptionMap map[string][]byte
var SynOption4 []byte
var SynOption6 []byte

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

func TFODaemon(srcAddr string, srcPort int, forward bool) {
	wg.Add(1)
	defer wg.Done()

	var filter string
	var layer uint8
	if forward {
		filter = fmt.Sprintf("ip.SrcAddr = %s and tcp.SrcPort == %d", srcAddr, srcPort)
		layer = 1
	} else {
		filter = fmt.Sprintf("inbound and ip.SrcAddr = %s and tcp.SrcPort == %d", srcAddr, srcPort)
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
		}

		packet.CalcNewChecksum(winDivert)
		_, err = winDivert.Send(packet)
		if err != nil {
			if LogLevel > 0 {
				log.Println(err)
			}
		}
	}
}

func TCPDaemon(address string, forward bool) {
	wg.Add(1)
	defer wg.Done()
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
			filter = fmt.Sprintf("!loopback and tcp.DstPort == %s", address[1:])
		} else {
			filter = fmt.Sprintf("ip.DstAddr = %s and tcp.DstPort == %d", tcpAddr.IP.String(), tcpAddr.Port)
		}
		layer = 1
	} else {
		if address[0] == ':' {
			filter = fmt.Sprintf("outbound and !loopback and tcp.DstPort == %s", address[1:])
		} else {
			filter = fmt.Sprintf("outbound and ip.DstAddr = %s and tcp.DstPort == %d", tcpAddr.IP.String(), tcpAddr.Port)
		}
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
					if LogLevel > 0 {
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
				if ipv6 {
					PortList6[srcPort] = nil
				} else {
					PortList4[srcPort] = nil
				}
			case 80:
				request := packet.Raw[ipheadlen+tcpheadlen:]
				host_offset, host_length = getHost(request)
			case 443:
				seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
				if !forward && info.Option&OPT_TFO != 0 {
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
						if info.Option&OPT_PSH != 0 {
							rawbuf[ipheadlen+13] = TCP_SYN | TCP_PSH
						} else {
							rawbuf[ipheadlen+13] = TCP_SYN
						}

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
					if seqNum == info.SeqNum+1 {
						hello := packet.Raw[ipheadlen+tcpheadlen:]
						host_offset, host_length = getSNI(hello)
					} else {
						if ipv6 {
							PortList6[srcPort] = nil
						} else {
							PortList4[srcPort] = nil
						}
					}
				}
			default:
				host_length = len(packet.Raw[ipheadlen+tcpheadlen:])
			}

			if info.Option != 0 && host_length > 0 {
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

				if (info.Option & OPT_SYN) != 0 {
					rawbuf[fakeipheadlen+13] = TCP_SYN

					seqNum := binary.BigEndian.Uint32(rawbuf[ipheadlen+4:])
					seqNum += 65536
					binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], seqNum)
					if (info.Option & OPT_ACK) != 0 {
						rawbuf[fakeipheadlen+13] |= TCP_ACK
					} else {
						binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], 0)
					}
				}

				fake_packet.Raw = rawbuf[:len(packet.Raw)]
				fake_packet.CalcNewChecksum(winDivert)

				if (info.Option & OPT_CSUM) != 0 {
					binary.BigEndian.PutUint16(rawbuf[fakeipheadlen+16:], 0)
				}

				if (info.Option & (OPT_ACK | OPT_SYN)) == 0 {
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

				if (info.Option & (OPT_ACK | OPT_SYN)) != 0 {
					_, err = winDivert.Send(&fake_packet)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
						continue
					}
					time.Sleep(time.Microsecond * 10)
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
			} else {
				_, err = winDivert.Send(packet)
				if err != nil {
					if LogLevel > 0 {
						log.Println(err)
					}
					continue
				}
			}
		} else if packet.Raw[ipheadlen+13] == TCP_SYN {
			dstAddr := packet.DstIP().String()
			config, ok := IPMap[dstAddr]

			if ok && config.Option != 0 {
				seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
				if ipv6 {
					PortList6[srcPort] = &ConnInfo{config.Option, seqNum, 0, config.TTL, config.MAXTTL}
				} else {
					PortList4[srcPort] = &ConnInfo{config.Option, seqNum, 0, config.TTL, config.MAXTTL}
				}

				tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4

				if !forward && (config.Option&OPT_TFO) != 0 {
					synOption := make([]byte, tcpheadlen-20)
					copy(synOption, packet.Raw[ipheadlen+20:])

					copy(rawbuf, packet.Raw)
					option, ok := OptionMap[dstAddr]

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
							go TFODaemon(dstAddr, tcpAddr.Port, forward)
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
		} else if (packet.Raw[ipheadlen+13] & TCP_ACK) != 0 {
			var info *ConnInfo
			if ipv6 {
				info = PortList6[srcPort]
			} else {
				info = PortList4[srcPort]
			}

			if info != nil {
				if !forward && info.Option&OPT_TFO != 0 {
					seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])

					ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:])
					ackNum += info.AckNum
					binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], ackNum)

					if seqNum == info.SeqNum+1 {
						if ackNum == 1 && info.AckNum == 0 {
							continue
						}

						tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
						packet.Raw[ipheadlen+12] = 5 << 4
						packet.Raw[ipheadlen+13] = TCP_RST | TCP_ACK
						packet.PacketLen = uint(ipheadlen + tcpheadlen)
						if ipv6 {
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(packet.PacketLen))
						} else {
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
						}
						packet.CalcNewChecksum(winDivert)

						_, err = winDivert.Send(packet)
						if err != nil {
							if LogLevel > 0 {
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

	winDivert, err := godivert.NewWinDivertHandleWithLayerFlags(filter, layer, 0)
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
