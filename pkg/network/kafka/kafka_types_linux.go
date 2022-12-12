// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -fsigned-char kafka_types.go

package kafka

type kafkaConnTuple struct {
	Saddr_h  uint64
	Saddr_l  uint64
	Daddr_h  uint64
	Daddr_l  uint64
	Sport    uint16
	Dport    uint16
	Netns    uint32
	Pid      uint32
	Metadata uint32
}

type ebpfKafkaTx struct {
	Tup                                kafkaConnTuple
	Request_api_key                    uint16
	Request_api_version                uint16
	Correlation_id                     uint32
	Tcp_seq                            uint32
	Current_offset_in_request_fragment uint32
	Request_fragment                   [320]byte
	Topic_name                         [80]int8
}
type kafkaBatch struct {
	Idx uint64
	Pos uint8
	Txs [15]ebpfKafkaTx
}
type kafkaBatchKey struct {
	Cpu uint32
	Num uint32
}

const (
	KAFKABatchSize  = 0xf
	KAFKABatchPages = 0x3
	KAFKABufferSize = 0x140

	kafkaProg = 0x0
)
