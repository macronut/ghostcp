package tcpioneer

import (
	"encoding/binary"
	"log"
	"net"
	"time"
)

var DNS string = ""

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
		if recvlen >= 1024 {
			return nil, nil
		}
		n, err := server.Read(data[recvlen:])
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

	binary.BigEndian.PutUint16(response6[8:10], 0)
	binary.BigEndian.PutUint16(response6[10:12], 0)
	//copy(response6[offset6:], response[offset4:])
	//offset6 += len(response) - offset4

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
		if ip4 != nil {
			if qtype == 1 {
				count++
				totalLen += 16
			}
		} else if qtype == 28 {
			count++
			totalLen += 28
		}
	}

	if count == 0 {
		return 0, nil
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

func AddECS(request []byte, ecs net.IP) []byte {
	if binary.BigEndian.Uint16(request[10:12]) > 0 {
		return request
	}
	request_ecs := make([]byte, 512)
	length := len(request)
	copy(request_ecs, request)
	binary.BigEndian.PutUint16(request_ecs[10:], 1) //ARCount

	request_ecs[length] = 0 //Name
	length++
	binary.BigEndian.PutUint16(request_ecs[length:], 41) // Type
	length += 2
	binary.BigEndian.PutUint16(request_ecs[length:], 4096) // UDP Payload
	length += 2
	request_ecs[length] = 0 // Highter bits in extended RCCODE
	length++
	request_ecs[length] = 0 // EDNS0 Version
	length++
	binary.BigEndian.PutUint16(request_ecs[length:], 0x800) // Z
	length += 2

	ecsip4 := ecs.To4()
	if ecsip4 != nil {
		binary.BigEndian.PutUint16(request_ecs[length:], 11) // Length
		length += 2
		binary.BigEndian.PutUint16(request_ecs[length:], 8) // Option Code
		length += 2
		binary.BigEndian.PutUint16(request_ecs[length:], 7) // Option Length
		length += 2
		binary.BigEndian.PutUint16(request_ecs[length:], 1) // Family
		length += 2
		request_ecs[length] = 24 // Source Netmask
		length++
		request_ecs[length] = 0 // Scope Netmask
		length++
		copy(request_ecs[length:], ecsip4[:3])
		length += 3
	} else {
		binary.BigEndian.PutUint16(request_ecs[length:], 15) // Length
		length += 2
		binary.BigEndian.PutUint16(request_ecs[length:], 8) // Option Code
		length += 2
		binary.BigEndian.PutUint16(request_ecs[length:], 11) // Option Length
		length += 2
		binary.BigEndian.PutUint16(request_ecs[length:], 2) // Family
		length += 2
		request_ecs[length] = 56 // Source Netmask
		length++
		request_ecs[length] = 0 // Scope Netmask
		length++
		copy(request_ecs[length:], ecs[:7])
		length += 7
	}

	return request_ecs[:length]
}
