package bruteforce

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"main/common"
	types "main/common"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type cpuBackend struct{}

func GetCPUBackend() Backend {
	return &cpuBackend{}
}

func (b *cpuBackend) Name() string {
	return "CPU"
}

func (b *cpuBackend) Available() bool {
	return true
}

func (b *cpuBackend) BruteforceV0Checksum(arguments types.CLIArgs) BruteforceResultGPU {
	accessKey := bruteforceCPU(arguments)

	return BruteforceResultGPU{
		Value: accessKey,
		Found: accessKey != "",
	}
}

func (b *cpuBackend) BruteforceV1HMAC(arguments types.CLIArgs) BruteforceResultGPU {
	accessKey := bruteforceCPU(arguments)

	return BruteforceResultGPU{
		Value: accessKey,
		Found: accessKey != "",
	}
}

func bruteforceCPU(arguments types.CLIArgs) string {
	packetData, err := hex.DecodeString(arguments.Packet())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding sample packet: %v\n", err)
		os.Exit(0)
	}

	threads := runtime.NumCPU()
	if arguments.BruteforceGoroutineCount() != 0 {
		threads = arguments.BruteforceGoroutineCount()
	}

	fmt.Printf("Bruteforcing valid access key using %d goroutines. This may take a long time...\n", threads)

	var wg sync.WaitGroup
	var accessKeyCounter uint64
	var found atomic.Bool
	var result atomic.Value
	total := uint64(0x100000000)
	progressPrinterDone := make(chan struct{})
	sigChan := make(chan os.Signal, 1)

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		found.Store(true)
	}()

	go func() {
		for {
			select {
			case <-progressPrinterDone:
				return
			default:
				fmt.Printf("\rChecked %d/%d possible access keys...", atomic.LoadUint64(&accessKeyCounter), total-1)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	var accessKeyValidator func(packetData []byte, possibleAccessKey string) bool

	if bytes.Equal(packetData[:2], []byte{0xEA, 0xD0}) {
		header := packetData[0x6:0xE]
		packetSignature := packetData[0xE:0x1E]
		optionsAndPayload := packetData[0x1E:]

		accessKeyValidator = func(packetData []byte, possibleAccessKey string) bool {
			accessKeyBytes := []byte(possibleAccessKey)

			accessKeySum := common.Sum[byte, uint32](accessKeyBytes)
			accessKeySumBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(accessKeySumBytes, accessKeySum)

			key := md5.Sum(accessKeyBytes)
			mac := hmac.New(md5.New, key[:])

			mac.Write(header)
			mac.Write(accessKeySumBytes)
			mac.Write(optionsAndPayload)

			return bytes.Equal(packetSignature, mac.Sum(nil))
		}
	} else {
		data := packetData[:len(packetData)-1]

		words := make([]uint32, len(data)/4)

		for i := 0; i < len(data)/4; i++ {
			words[i] = binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
		}

		temp := common.Sum[uint32, uint32](words) & 0xFFFFFFFF

		precomputedChecksum := common.Sum[byte, uint32](data[len(data)&^3:])

		tempBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(tempBytes, temp)

		precomputedChecksum += common.Sum[byte, uint32](tempBytes)

		accessKeyValidator = func(packetData []byte, possibleAccessKey string) bool {
			checksum := precomputedChecksum + common.Sum[byte, uint32]([]byte(possibleAccessKey))

			return byte(checksum&0xFF) == packetData[len(packetData)-1]
		}
	}

	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				if found.Load() {
					return
				}

				nextValue := atomic.AddUint64(&accessKeyCounter, 1) - 1
				if nextValue >= total {
					return
				}

				possibleAccessKey := fmt.Sprintf("%08x", nextValue)

				if accessKeyValidator(packetData, possibleAccessKey) {
					if found.CompareAndSwap(false, true) {
						result.Store(possibleAccessKey)
					}
					return
				}
			}
		}()
	}

	wg.Wait()
	close(progressPrinterDone)
	signal.Stop(sigChan)

	fmt.Printf("\rChecked %d/%d possible access keys...\n", accessKeyCounter, total-1)

	if v := result.Load(); v != nil {
		return v.(string)
	}

	return ""
}
