//go:build darwin

package bruteforce

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Metal -framework Foundation

#include "cgo/bruteforce.h"
#include "cgo/metal/bruteforce.m"
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	types "main/common"
	"os"
)

type metalBackend struct{}

func GetMetalBackend() Backend {
	return &metalBackend{}
}

func (b *metalBackend) Name() string {
	return "Metal"
}

func (b *metalBackend) Available() bool {
	return true // TODO - Check if Metal is actually available on the current Apple device?
}

func (b *metalBackend) BruteforceV0Checksum(arguments types.CLIArgs) BruteforceResultGPU {
	packetData, err := hex.DecodeString(arguments.Packet())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding sample packet: %v\n", err)
		os.Exit(0)
	}

	data := packetData[:len(packetData)-1]
	targetChecksum := packetData[len(packetData)-1]

	result := C.bruteforce_prudpv0_checksum(
		(*C.uint8_t)(&data[0]),
		C.uint32_t(len(data)),
		C.uint8_t(targetChecksum),
	)

	return BruteforceResultGPU{
		Found: bool(result.found),
		Value: fmt.Sprintf("%08x", result.value),
	}
}

func (b *metalBackend) BruteforceV1HMAC(arguments types.CLIArgs) BruteforceResultGPU {
	packetData, err := hex.DecodeString(arguments.Packet())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding sample packet: %v\n", err)
		os.Exit(0)
	}

	header := packetData[0x6:0xE]
	packetSignature := packetData[0xE:0x1E]
	optionsAndPayload := packetData[0x1E:]

	result := C.bruteforce_prudpv1_hmac(
		(*C.uint8_t)(&header[0]),
		(*C.uint8_t)(&packetSignature[0]),
		(*C.uint8_t)(&optionsAndPayload[0]),
		C.uint32_t(len(optionsAndPayload)),
	)

	return BruteforceResultGPU{
		Found: bool(result.found),
		Value: fmt.Sprintf("%08x", result.value),
	}
}
