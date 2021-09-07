package tcpioneer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/macronut/godivert"
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
var SynOption []byte

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

const (
	TCP_NONE = iota
	TCP_DNS
	TCP_HTTP
	TCP_TLS
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

func TCPRecv(srcPort int, forward bool) {
	if (TFOEnable || RSTFilterEnable || DetectEnable) == false {
		return
	}

	var filter string
	var layer uint8
	if forward {
		filter = fmt.Sprintf("tcp.SrcPort == %d and (", srcPort)
		layer = 1
	} else {
		filter = fmt.Sprintf("inbound and tcp.SrcPort == %d and (", srcPort)
		layer = 0
	}

	count := 0
	if TFOEnable {
		filter += "tcp.Syn"
		count++
	}
	if RSTFilterEnable {
		if count > 0 {
			filter += " or "
		}
		filter += "tcp.Rst"
		count++
	}
	if DetectEnable {
		if count > 0 {
			filter += " or "
		}
		filter += "tcp.DstPort < 5"
		count++
	}
	filter += ")"

	mutex.Lock()
	winDivert, err := godivert.WinDivertOpen(filter, layer, 1, 0)
	mutex.Unlock()

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
				switch dstPort {
				case 1:
					BadIPMap[packet.SrcIP().String()] = true
					continue
				case 2:
					goodIP := packet.SrcIP()
					_, ok := IPMap[goodIP.String()]
					if ok {
						continue
					}

					myIP := packet.DstIP()
					packet.SetSrcIP(myIP)
					packet.SetDstIP(goodIP)
					srcPort := binary.BigEndian.Uint16(packet.Raw[ipheadlen:])
					packet.SetSrcPort(dstPort)
					packet.SetDstPort(srcPort)
					seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
					ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:])
					binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], ackNum)
					binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], seqNum+1)
					packet.Raw[ipheadlen+13] = TCP_RST | TCP_ACK
					packet.Addr.Data = 1 << 4

					packet.CalcNewChecksum(winDivert)
					_, err := winDivert.Send(packet)
					if err != nil {
						log.Println(err)
					}

					if ScanURL == "" {
						fmt.Println(goodIP, "found")
					} else {
						go CheckServer(ScanURL, goodIP, ScanTimeout)
					}
					continue
				case 3:
					tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
					optStart := ipheadlen + 20
					option := packet.Raw[optStart : ipheadlen+tcpheadlen]
					cookies := getCookies(option)
					if cookies != nil {
						tmp_cookies := make([]byte, len(cookies))
						copy(tmp_cookies, cookies)
						CookiesMap[packet.SrcIP().String()] = tmp_cookies
					}
					continue
				default:
					var info *ConnInfo
					if ipv6 {
						info = PortList6[dstPort]
					} else {
						info = PortList4[dstPort]
					}

					if info != nil && info.Option&OPT_TFO != 0 {
						ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:])
						ackNum = info.SeqNum + 1
						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], ackNum)
						packet.CalcNewChecksum(winDivert)
					}
				}

			} else if packet.Raw[ipheadlen+13]|TCP_RST != 0 {
				if DetectEnable {
					dstPort, _ := packet.DstPort()
					if dstPort == 1 {
						BadIPMap[packet.SrcIP().String()] = true
						continue
					}
				}

				var info *ConnInfo
				if ipv6 {
					info = PortList6[dstPort]
				} else {
					info = PortList4[dstPort]
				}

				if info != nil && info.Option&OPT_NORST != 0 {
					continue
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

const domainBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

func SendFakePacket(winDivert *godivert.WinDivertHandle, info *ConnInfo, packet *godivert.Packet, host_offset int, host_length int, count int) (int, error) {
	rawbuf := make([]byte, 1500)

	ipv6 := packet.Raw[0]>>4 == 6
	var ipheadlen int
	if ipv6 {
		ipheadlen = 40
	} else {
		ipheadlen = int(packet.Raw[0]&0xF) * 4
	}

	tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4

	fake_packet := *packet
	copy(rawbuf, packet.Raw)

	total_host_offset := ipheadlen + tcpheadlen + host_offset
	if host_length == 1 { //DNS
		dot := int(rawbuf[total_host_offset] + 1)
		for i := 1; i < int(packet.PacketLen); i++ {
			if i == dot {
				off := rawbuf[i+total_host_offset]
				if off == 0 {
					host_length = i
					break
				}
				dot += int(off) + 1
			} else {
				rawbuf[i+total_host_offset] = domainBytes[rand.Intn(len(domainBytes))]
			}
		}
	} else {
		for i := total_host_offset; i < total_host_offset+host_length-3; i++ {
			if rawbuf[i] != '.' {
				rawbuf[i] = domainBytes[rand.Intn(len(domainBytes))]
			}
		}
	}

	var err error

	if (info.Option & OPT_WCSUM) != 0 {
		fake_packet.Raw = rawbuf[:len(packet.Raw)]

		for i := 0; i < count; i++ {
			_, err = winDivert.Send(&fake_packet)
			if err != nil {
				return 0, err
			}
		}
	}

	if (info.Option & OPT_TTL) > 0 {
		if ipv6 {
			rawbuf[7] = byte(info.TTL)
		} else {
			rawbuf[8] = byte(info.TTL)
		}
		fake_packet.Raw = rawbuf[:len(packet.Raw)]

		fake_packet.CalcNewChecksum(winDivert)

		for i := 0; i < count; i++ {
			_, err = winDivert.Send(&fake_packet)
			if err != nil {
				return 0, err
			}
		}
	}

	if (info.Option & OPT_WACK) != 0 {
		copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])
		ackNum := binary.BigEndian.Uint32(rawbuf[ipheadlen+8:])
		ackNum += uint32(binary.BigEndian.Uint16(rawbuf[ipheadlen+14:]))
		binary.BigEndian.PutUint32(rawbuf[ipheadlen+8:], ackNum)
		fake_packet.Raw = rawbuf[:len(packet.Raw)]

		fake_packet.CalcNewChecksum(winDivert)

		for i := 0; i < count; i++ {
			_, err = winDivert.Send(&fake_packet)
			if err != nil {
				return 0, err
			}
		}
	}

	if (info.Option & OPT_IPOPT) != 0 {
		copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])
		fakeipheadlen := ipheadlen + 32
		copy(rawbuf[fakeipheadlen:], packet.Raw[ipheadlen:ipheadlen+tcpheadlen])
		if ipv6 {
		} else {
			rawbuf[0] = rawbuf[0]&0xF0 | byte(fakeipheadlen/4)
		}
		for i := 0; i < 31; i++ {
			rawbuf[ipheadlen+i] = 1
		}
		rawbuf[ipheadlen+31] = 0
		fake_packet.Raw = rawbuf[:len(packet.Raw)]

		fake_packet.CalcNewChecksum(winDivert)

		for i := 0; i < count; i++ {
			_, err = winDivert.Send(&fake_packet)
			if err != nil {
				return 0, err
			}
		}
	}

	if (info.Option & OPT_BAD) != 0 {
		copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])
		rawbuf[ipheadlen+12] = 4 << 4
		fake_packet.Raw = rawbuf[:len(packet.Raw)]

		fake_packet.CalcNewChecksum(winDivert)

		for i := 0; i < count; i++ {
			_, err = winDivert.Send(&fake_packet)
			if err != nil {
				return 0, err
			}
		}
	}

	if info.Option&OPT_SEQ != 0 {
		seqNum := binary.BigEndian.Uint32(rawbuf[ipheadlen+4:])
		seqNum -= 32767
		binary.BigEndian.PutUint32(rawbuf[ipheadlen+4:], seqNum)
		fake_packet.Raw = rawbuf[:len(packet.Raw)]

		fake_packet.CalcNewChecksum(winDivert)
		_, err = winDivert.Send(&fake_packet)
		if err != nil {
			return 0, err
		}
	}

	if (info.Option & OPT_WMD5) != 0 {
		copy(rawbuf, packet.Raw[:ipheadlen+tcpheadlen])
		copy(rawbuf[ipheadlen+20:], []byte{19, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		rawbuf[ipheadlen+12] = 10 << 4
		copy(rawbuf[ipheadlen+40:], rawbuf[ipheadlen+tcpheadlen:len(packet.Raw)])
		fake_packet.Raw = rawbuf[:len(packet.Raw)]

		fake_packet.CalcNewChecksum(winDivert)

		for i := 0; i < count; i++ {
			_, err = winDivert.Send(&fake_packet)
			if err != nil {
				return 0, err
			}
		}
	}

	return host_length, nil
}

func TCPDetection(winDivert *godivert.WinDivertHandle, winDivertAddr godivert.WinDivertAddress, srcIP []byte, ips []string, port, ttl int) []string {
	var packet godivert.Packet
	packet.PacketLen = 40
	winDivertAddr.Data = 1 << 4
	packet.Addr = &winDivertAddr
	packet.Raw = []byte{
		0x45, 0, 0, 40,
		0, 0, 0x40, 0,
		byte(ttl), 6, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 1, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0x50, TCP_SYN, 0, 0,
		0, 0, 0, 0}

	if srcIP != nil {
		copy(packet.Raw[12:], srcIP)
	} else {
		srcIP := getMyIPv4()
		copy(packet.Raw[12:], srcIP)
	}

	binary.BigEndian.PutUint16(packet.Raw[22:], uint16(port))

	for _, addr := range ips {
		ip := net.ParseIP(addr)
		ip4 := ip.To4()
		if ip4 != nil {
			copy(packet.Raw[16:], ip4)
			packet.CalcNewChecksum(winDivert)
			_, err := winDivert.Send(&packet)
			if err != nil {
				log.Println(err, packet)
			}
		}
	}

	time.Sleep(time.Millisecond * 100)

	var new_ips []string = nil
	for _, ip := range ips {
		bad, ok := BadIPMap[ip]
		if !ok || !bad {
			new_ips = append(new_ips, ip)
		}
	}

	return new_ips
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

	mutex.Lock()
	winDivert, err := godivert.WinDivertOpen(filter, layer, 1, 0)
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
		tmp_rawbuf := make([]byte, 1500)

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

				if payloadLen == 0 {
					if info.Option&OPT_SYN != 0 {
						_, err := winDivert.Send(packet)

						seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4:])
						ackNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+8:])
						if seqNum != info.SeqNum+1 {
							continue
						}
						/*
							if ipv6 {
								packet.Raw[7] = byte(info.TTL)
							} else {
								packet.Raw[8] = byte(info.TTL)
							}
						*/
						var offset uint32 = 32768

						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], info.SeqNum-offset)
						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], 0)
						packet.Raw[ipheadlen+13] = TCP_SYN
						packet.CalcNewChecksum(winDivert)
						_, err = winDivert.Send(packet)
						if err != nil {
							log.Println(err)
						}

						seqNum -= offset
						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], seqNum)
						binary.BigEndian.PutUint32(packet.Raw[ipheadlen+8:], ackNum)
						packet.Raw[ipheadlen+13] = TCP_ACK
						packet.CalcNewChecksum(winDivert)
						_, err = winDivert.Send(packet)
						if err != nil {
							log.Println(err)
						}

						copy(rawbuf, packet.Raw)
						packet.PacketLen += 16
						if ipv6 {
							binary.BigEndian.PutUint16(rawbuf[4:], uint16(int(packet.PacketLen)-ipheadlen))
						} else {
							binary.BigEndian.PutUint16(rawbuf[2:], uint16(packet.PacketLen))
						}
						rawbuf[ipheadlen+13] = TCP_PSH | TCP_ACK
						packet.Raw = rawbuf[:packet.PacketLen]
						packet.CalcNewChecksum(winDivert)
						_, err = winDivert.Send(packet)
						if err != nil {
							log.Println(err)
						}
						continue
					}

					_, err = winDivert.Send(packet)
					continue
				}

				appLayer := TCP_NONE

				host_offset := 0
				host_length := 0
				switch dstPort {
				case 53:
					appLayer = TCP_DNS
				case 80:
					appLayer = TCP_HTTP
				case 443:
					appLayer = TCP_TLS
				default:
					appLayer = TCP_NONE
				}

				switch appLayer {
				case TCP_DNS:
					if payloadLen > 0 {
						if len(packet.Raw[ipheadlen+tcpheadlen:]) > 21 {
							host_offset = 14
							host_length = 1
						}
						if ipv6 {
							PortList6[srcPort] = nil
						} else {
							PortList4[srcPort] = nil
						}
					}
				case TCP_HTTP:
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
				case TCP_TLS:
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
							hello := packet.Raw[ipheadlen+tcpheadlen:]
							host_offset, host_length = getSNI(hello)
						}
					} else {
						if info.Option&OPT_SAT != 0 && payloadLen > 0 {
							host_offset = 0
							host_length = payloadLen
						} else {
							if ipv6 {
								PortList6[srcPort] = nil
							} else {
								PortList4[srcPort] = nil
							}
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

				if (info.Option&OPT_SSEG) != 0 && payloadLen > 4 {
					copy(tmp_rawbuf, packet.Raw[:ipheadlen+tcpheadlen+4])
					if ipv6 {
						binary.BigEndian.PutUint16(tmp_rawbuf[4:], uint16(tcpheadlen+4))
						if info.MAXTTL > 0 {
							tmp_rawbuf[7] = info.MAXTTL
						}
					} else {
						binary.BigEndian.PutUint16(tmp_rawbuf[2:], uint16(ipheadlen+tcpheadlen+4))
						if info.MAXTTL > 0 {
							tmp_rawbuf[8] = info.MAXTTL
						}
					}

					prefix_packet := *packet
					prefix_packet.Raw = tmp_rawbuf[:ipheadlen+tcpheadlen+4]
					prefix_packet.PacketLen = uint(ipheadlen + tcpheadlen + 4)
					prefix_packet.CalcNewChecksum(winDivert)
					_, err = winDivert.Send(&prefix_packet)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
						continue
					}
				}

				count := 1
				if (info.Option & 0xFFFF) != 0 {
					if info.Option&OPT_MODE2 == 0 {
						if info.Option&OPT_DF != 0 {
							host_length, err = SendFakePacket(winDivert, info, packet, host_offset, host_length, 2)
							_, err = winDivert.Send(packet)
							if err != nil {
								if LogLevel > 0 {
									log.Println(err)
								}
							}
							continue
						}
						host_length, err = SendFakePacket(winDivert, info, packet, host_offset, host_length, count)
						if err != nil {
							if LogLevel > 0 {
								log.Println(err)
							}
							continue
						}
					} else {
						count = 2
					}
				}

				if info.Option&OPT_DF != 0 {
					winDivert.Send(packet)
					continue
				}

				if info.Option&OPT_MD5 != 0 {
					copy(tmp_rawbuf, packet.Raw[ipheadlen+tcpheadlen:])
					copy(packet.Raw[ipheadlen+20:], []byte{19, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
					packet.Raw[ipheadlen+12] = 10 << 4
					tcpheadlen = 40
					copy(packet.Raw[ipheadlen+20:], tmp_rawbuf[:int(packet.PacketLen)-ipheadlen-tcpheadlen])
				}

				host_cut_offset := host_offset + host_length/2
				total_cut_offset := ipheadlen + tcpheadlen + host_cut_offset

				copy(tmp_rawbuf, packet.Raw[:total_cut_offset])

				if (info.Option & OPT_NOFLAG) != 0 {
					tmp_rawbuf[ipheadlen+13] = 0
				} else {
					tmp_rawbuf[ipheadlen+13] &= ^TCP_PSH
				}

				seqNum := binary.BigEndian.Uint32(packet.Raw[ipheadlen+4 : ipheadlen+8])
				prefix_packet := *packet
				if (info.Option&OPT_SSEG) != 0 && payloadLen > 4 {
					copy(tmp_rawbuf[ipheadlen+tcpheadlen:], packet.Raw[ipheadlen+tcpheadlen+4:total_cut_offset])
					totallen := uint16(total_cut_offset - 4)
					binary.BigEndian.PutUint32(tmp_rawbuf[ipheadlen+4:], seqNum+4)
					if ipv6 {
						binary.BigEndian.PutUint16(tmp_rawbuf[4:], totallen-uint16(ipheadlen))
						if info.MAXTTL > 0 {
							tmp_rawbuf[7] = info.MAXTTL
						}
					} else {
						binary.BigEndian.PutUint16(tmp_rawbuf[2:], totallen)
						if info.MAXTTL > 0 {
							tmp_rawbuf[8] = info.MAXTTL
						}
					}

					prefix_packet.Raw = tmp_rawbuf[:totallen]
					prefix_packet.PacketLen = uint(totallen)
				} else {
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

					prefix_packet.Raw = tmp_rawbuf[:total_cut_offset]
					prefix_packet.PacketLen = uint(total_cut_offset)
				}
				prefix_packet.CalcNewChecksum(winDivert)
				_, err = winDivert.Send(&prefix_packet)
				if err != nil {
					if LogLevel > 0 {
						log.Println(err)
					}
					continue
				}

				if (info.Option & 0xFFFF) != 0 {
					_, err = SendFakePacket(winDivert, info, packet, host_offset, host_length, count)
					if err != nil {
						if LogLevel > 0 {
							log.Println(err)
						}
						continue
					}
				}

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
				dstIP := packet.DstIP()
				dstAddr := dstIP.String()
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

					if config.Option&(OPT_TFO|OPT_WTFO) != 0 {
						if config.Option&OPT_TFO != 0 {
							SynOption = make([]byte, tcpheadlen-20)
							copy(SynOption, packet.Raw[ipheadlen+20:])

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
								binary.BigEndian.PutUint16(rawbuf[ipheadlen:], 3)
								packet.PacketLen += 4
								rawbuf[ipheadlen+12] += 1 << 4
								rawbuf[ipheadlen+tcpheadlen] = 34
								rawbuf[ipheadlen+tcpheadlen+1] = 2
								rawbuf[ipheadlen+tcpheadlen+2] = 1
								rawbuf[ipheadlen+tcpheadlen+3] = 1
							}
						} else {
							cookiesLen := 16
							optLen := cookiesLen + 2
							offset := byte((optLen + 3) / 4)
							rawbuf[ipheadlen+12] += offset << 4
							rawbuf[int(packet.PacketLen)] = 34
							rawbuf[int(packet.PacketLen)+1] = byte(optLen)
							packet.PacketLen += uint(offset * 4)

							rawbuf[packet.PacketLen] = 0x00
							rawbuf[packet.PacketLen+1] = 0x00
							rawbuf[packet.PacketLen+2] = 0x00
							rawbuf[packet.PacketLen+3] = 0x00
							rawbuf[packet.PacketLen+4] = 0x00
							packet.PacketLen += 512
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
					/*
						if config.Option&OPT_SYN != 0 {
							binary.BigEndian.PutUint32(packet.Raw[ipheadlen+4:], seqNum-32767)
							packet.CalcNewChecksum(winDivert)
						}
					*/
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
					logPrintln(3, packet.DstIP(), tcpAddr.Port)
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

func NAT64(ipv4 net.IP, ipv6 net.IP, forward bool) {
	wg.Add(1)
	defer wg.Done()

	copy(ipv6[12:], ipv4[:4])
	var filter string
	var layer uint8
	if forward {
		filter = fmt.Sprintf("ip.DstAddr=%s or ipv6.SrcAddr=%s", ipv4.String(), ipv6.String())
		layer = 1
	} else {
		filter = fmt.Sprintf("(outbound and ip.DstAddr=%s) or (inbound and ipv6.SrcAddr=%s)", ipv4.String(), ipv6.String())
		layer = 0
	}

	mutex.Lock()
	winDivert, err := godivert.WinDivertOpen(filter, layer, 0, 0)
	mutex.Unlock()
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
	mss := uint16(1440)

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
			if packet.PacketLen > 1500-20 {
				continue
			}

			ipheadlen := int(packet.Raw[0]&0xF) * 4
			payloadLen := int(packet.PacketLen) - ipheadlen

			if packet.Raw[9] == 6 {
				if packet.Raw[ipheadlen+13] == TCP_SYN {
					tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
					if tcpheadlen >= 24 {
						tcpOption := packet.Raw[ipheadlen+20]
						if tcpOption == 2 {
							mss = binary.BigEndian.Uint16(packet.Raw[ipheadlen+22:])
							mss -= 20
							binary.BigEndian.PutUint16(packet.Raw[ipheadlen+22:], mss)
						}
					}
				}
			}

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

			if packet.Raw[6] == 6 {
				if packet.Raw[ipheadlen+13] == TCP_SYN|TCP_ACK {
					tcpheadlen := int(packet.Raw[ipheadlen+12]>>4) * 4
					if tcpheadlen >= 24 {
						tcpOption := packet.Raw[ipheadlen+20]
						if tcpOption == 2 {
							if mss < binary.BigEndian.Uint16(packet.Raw[ipheadlen+22:]) {
								binary.BigEndian.PutUint16(packet.Raw[ipheadlen+22:], mss)
							}
						}
					}
				}
			}

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

type ProxyInfo struct {
	SrcIP net.IP
	DstIP net.IP
	Port  uint16
}

var ProxyList4 [65536]*ProxyInfo
var ProxyList6 [65536]*ProxyInfo

func ProxyRedirect(forward bool) {
	var filter string
	var layer uint8
	if forward {
		filter = "tcp.SrcPort=6"
		layer = 1
	} else {
		filter = "tcp.SrcPort=6"
		layer = 0
	}

	mutex.Lock()
	winDivert, err := godivert.WinDivertOpen(filter, layer, 0, 0)
	mutex.Unlock()

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
			var info *ProxyInfo
			if ipv6 {
				info = ProxyList6[dstPort]
			} else {
				info = ProxyList4[dstPort]
			}

			if info != nil {
				packet.SetDstIP(info.SrcIP)
				packet.SetSrcIP(info.DstIP)
				packet.SetSrcPort(info.Port)
				packet.CalcNewChecksum(winDivert)
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
