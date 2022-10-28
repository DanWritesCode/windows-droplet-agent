// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"github.com/digitalocean/droplet-agent/internal/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// offsets in TCP header
const (
	offSrcPort    = 0
	offDestPort   = 2
	offSeqNum     = 4
	offAckNum     = 8
	offTCPFlags   = 12
	offWindowSize = 14
	offCheckSum   = 16
	offUrgent     = 18
	offOption     = 20
)

const (
	lenIPHeader = 20
)

const maxPacketBuf = 512

// NewTCPPacketSniffer returns a new TCP packet sniffer
func NewTCPPacketSniffer() TCPPacketSniffer {
	return &tcpPacketSniffer{
		tcpPacketSnifferHelper: newTCPPacketSnifferHelper(),
	}
}

type tcpPacketSnifferHelper interface {
	ToBpfFilters(identifier *TCPPacketIdentifier) ([]bpf.Instruction, error)
	SocketWithBPFFilter(filter []bpf.Instruction) (*pcap.Handle, error)
	UnmarshalTCPPacket(in []byte) (*TCPPacket, error)
}

// tcpPacketSniffer implementation for linux
type tcpPacketSniffer struct {
	tcpPacketSnifferHelper

	fd *pcap.Handle
}

func (s *tcpPacketSniffer) Capture(identifier *TCPPacketIdentifier) (<-chan *TCPPacket, error) {
	filter, err := s.ToBpfFilters(identifier)
	if err != nil {
		return nil, err
	}

	fd, err := s.SocketWithBPFFilter(filter)
	if err != nil {
		return nil, err
	}
	s.fd = fd
	packetChan := make(chan *TCPPacket)
	go s.snifferLoop(packetChan)
	return packetChan, nil
}

func (s *tcpPacketSniffer) Stop() {
	s.fd.Close()
}

func (s *tcpPacketSniffer) snifferLoop(packetChan chan<- *TCPPacket) {
	minMsgLen := lenIPHeader + offOption
	src := gopacket.NewPacketSource(s.fd, s.fd.LinkType())
	for {
		n, err := src.NextPacket()
		if err != nil {
			log.Error("failed to read from socket. %v", err)
			continue
		}
		if len(n.Data()) < minMsgLen {
			// less than 40 bytes (len(IP packet header) + len(minimum TCP header))
			log.Error("invalid message: insufficient read [%d]", n)
			continue
		}
		packet, err := s.UnmarshalTCPPacket(n.Data())
		if err != nil {
			log.Error("failed to unmarshal TCP packet: %v", err)
			continue
		}
		packetChan <- packet
	}
}
