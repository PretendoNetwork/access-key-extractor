package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/PretendoNetwork/nex-go/v2"
)

const (
	CHUNK_SIZE         = 64 * 1024 // * 64k chunks seems fine?
	CHUNK_OVERLAP_SIZE = 16        // * Size of an 8 character UTF16 string
	UTF8_CHAR_WIDTH    = 1
	UTF16_CHAR_WIDTH   = 2
)

type CLIArgs struct {
	ShowHelp            bool
	ROMPath             string
	Packet              string
	PreferEncoding      string
	Bruteforce          bool
	BruteforceStopAfter int
}

type PossibleAccessKey struct {
	Value          string
	Encoding       string
	NULLTerminated bool
}

func extractPossibleAccessKey(arguments CLIArgs) ([]string, error) {
	file, err := os.Open(arguments.ROMPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	possibleAccessKeys := make([]PossibleAccessKey, 0)
	reader := bufio.NewReaderSize(file, CHUNK_SIZE)

	offset := int64(0)
	buffer := make([]byte, CHUNK_SIZE)
	overlap := make([]byte, 0, CHUNK_OVERLAP_SIZE) // * File is being read in chunks, so overlap the chunks a bit to account for strings across chunk boundaries

	for {
		read, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, err
		}

		if read == 0 {
			break
		}

		chunk := append(overlap, buffer[:read]...)
		possibleAccessKeys = append(possibleAccessKeys, extractPossibleAccessKeys(chunk, UTF8_CHAR_WIDTH, nil)...)
		possibleAccessKeys = append(possibleAccessKeys, extractPossibleAccessKeys(chunk, UTF16_CHAR_WIDTH, binary.LittleEndian)...)
		possibleAccessKeys = append(possibleAccessKeys, extractPossibleAccessKeys(chunk, UTF16_CHAR_WIDTH, binary.BigEndian)...)

		overlapSize := min(len(chunk), CHUNK_OVERLAP_SIZE)
		overlap = append(overlap[:0], chunk[len(chunk)-overlapSize:]...)

		offset += int64(read)

		if err == io.EOF {
			break
		}
	}

	seenAccessKeys := make([]string, 0)
	possibleAccessKeysDeduplicated := make([]PossibleAccessKey, 0)

	for _, possibleAccessKey := range possibleAccessKeys {
		if !slices.Contains(seenAccessKeys, possibleAccessKey.Value) {
			seenAccessKeys = append(seenAccessKeys, possibleAccessKey.Value)
			possibleAccessKeysDeduplicated = append(possibleAccessKeysDeduplicated, possibleAccessKey)
		}
	}

	fileExtension := filepath.Ext(arguments.ROMPath)
	preferEncoding := "UTF8"

	if fileExtension == ".code" {
		// * Assume 3DS dump
		preferEncoding = "UTF16LE"
	} else if fileExtension == ".elf" {
		// * Assume Wii U dump
		preferEncoding = "UTF16BE"
	}

	if arguments.PreferEncoding != "" {
		preferEncoding = arguments.PreferEncoding
	}

	slices.SortStableFunc(possibleAccessKeysDeduplicated, func(a, b PossibleAccessKey) int {
		// * First step: Reorder based on the preferred string encoding
		aPreferred := a.Encoding == preferEncoding
		bPreferred := b.Encoding == preferEncoding
		if aPreferred != bPreferred {
			if aPreferred {
				return -1
			}

			return 1
		}

		// * Second step: Reorder based on whether or not the string ended with a NULL terminator
		if a.NULLTerminated != b.NULLTerminated {
			if a.NULLTerminated {
				return -1
			}

			return 1
		}

		return 0
	})

	possibleAccessKeyValues := make([]string, 0)

	for _, possibleAccessKey := range possibleAccessKeysDeduplicated {
		possibleAccessKeyValues = append(possibleAccessKeyValues, possibleAccessKey.Value)
	}

	return possibleAccessKeyValues, nil
}

func extractPossibleAccessKeys(chunk []byte, charWidth int, order binary.ByteOrder) []PossibleAccessKey {
	possibleAccessKeys := make([]PossibleAccessKey, 0)
	stringBuffer := make([]uint16, 0, 8)
	var lastChar uint16

	checkStringBuffer := func() {
		if len(stringBuffer) == 8 {
			nullTerminated := lastChar == 0x00

			if charWidth == 1 {
				bytes := make([]byte, 8)
				for i, u16 := range stringBuffer {
					bytes[i] = byte(u16)
				}

				possibleAccessKeys = append(possibleAccessKeys, PossibleAccessKey{
					Value:          string(bytes),
					Encoding:       "UTF8",
					NULLTerminated: nullTerminated,
				})
			} else {
				if order == binary.BigEndian {
					possibleAccessKeys = append(possibleAccessKeys, PossibleAccessKey{
						Value:          string(utf16.Decode(stringBuffer)),
						Encoding:       "UTF16BE",
						NULLTerminated: nullTerminated,
					})
				} else {
					possibleAccessKeys = append(possibleAccessKeys, PossibleAccessKey{
						Value:          string(utf16.Decode(stringBuffer)),
						Encoding:       "UTF16LE",
						NULLTerminated: nullTerminated,
					})
				}
			}
		}
	}

	for i := 0; i < len(chunk); i += charWidth {
		if charWidth == 1 {
			lastChar = uint16(chunk[i])
		} else {
			lastChar = order.Uint16(chunk[i:])
		}

		if lastChar <= 0x7F && isLowercaseHex(byte(lastChar)) {
			stringBuffer = append(stringBuffer, lastChar)
		} else {
			checkStringBuffer()
			stringBuffer = stringBuffer[:0]
		}
	}

	checkStringBuffer() // * Catch strings at the very end of a chunk

	return possibleAccessKeys
}

func isLowercaseHex(char byte) bool {
	return (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')
}

func checkPacket(packetData []byte, possibleAccessKeys []string) []string {
	var wg sync.WaitGroup
	results := make(chan string, len(possibleAccessKeys))
	validAccessKeys := make([]string, 0)

	for _, possibleAccessKey := range possibleAccessKeys {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if checkPossibleAccessKey(packetData, possibleAccessKey) {
				results <- possibleAccessKey
			}
		}()
	}

	wg.Wait()
	close(results)

	for key := range results {
		validAccessKeys = append(validAccessKeys, key)
	}

	return validAccessKeys
}

func bruteforce(arguments CLIArgs) []string {
	packetData, err := hex.DecodeString(arguments.Packet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding sample packet: %v\n", err)
		os.Exit(0)
	}

	fmt.Printf("Bruteforcing valid access keys using %d CPU cores. May find multiple valid access keys, there is no way to know which is the original. This may take a long time...\n", runtime.NumCPU())

	var wg sync.WaitGroup
	var accessKeyCounter uint32
	var validCounter uint32
	var resultsMu sync.Mutex
	var manualStopped atomic.Bool
	validAccessKeys := make([]string, 0) // * Using a mutex protected slice here instead of a channel since allocating space for a 0xFFFFFFFF entry channel kills memory
	total := uint32(0xFFFFFFFF)
	progressPrinterDone := make(chan struct{})
	stopAfter := uint32(arguments.BruteforceStopAfter)
	sigChan := make(chan os.Signal, 1) // * Capturing CTRL+C inputs so that we can just print any valid access keys that were found when the user quits the program

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		manualStopped.Store(true)
	}()

	go func() {
		for {
			select {
			case <-progressPrinterDone:
				return
			default:
				fmt.Printf("\rChecked %d/%d possible access keys (found %d valid)...", atomic.LoadUint32(&accessKeyCounter), total, atomic.LoadUint32(&validCounter))
				time.Sleep(100 * time.Millisecond) // * Stops the printer from flashing sometimes
			}
		}
	}()

	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				if manualStopped.Load() {
					return
				}

				if stopAfter != 0 && stopAfter <= atomic.LoadUint32(&validCounter) {
					return
				}

				nextValue := atomic.AddUint32(&accessKeyCounter, 1) - 1
				if nextValue >= total {
					return
				}

				possibleAccessKey := fmt.Sprintf("%08x", nextValue)

				if checkPossibleAccessKey(packetData, possibleAccessKey) {
					resultsMu.Lock()
					validAccessKeys = append(validAccessKeys, possibleAccessKey)
					resultsMu.Unlock()
					atomic.AddUint32(&validCounter, 1)
				}
			}
		}()
	}

	wg.Wait()
	close(progressPrinterDone)
	signal.Stop(sigChan)

	fmt.Printf("\rChecked %d/%d possible access keys (found %d valid)...\n", accessKeyCounter, total, validCounter)

	return validAccessKeys
}

func checkPossibleAccessKey(packetData []byte, possibleAccessKey string) bool {
	valid := false
	server := nex.NewPRUDPServer()
	readStream := nex.NewByteStreamIn(packetData, nil, nil)

	server.AccessKey = possibleAccessKey

	if bytes.Equal(packetData[:2], []byte{0xEA, 0xD0}) {
		packet, err := nex.NewPRUDPPacketV1(server, nil, readStream)
		if err != nil {
			return false
		}

		// * HACK - nex-go doesn't have a way to check the v1 signature directly,
		// *        so just re-encode the packet directly and check if it matches
		packet.SetSignature(packet.CalculateSignature(nil, nil))

		valid = bytes.Equal(packetData, packet.Bytes())
	} else {
		_, err := nex.NewPRUDPPacketV0(server, nil, readStream)
		valid = err == nil // * The v0 decoder validates the checksum for us
	}

	return valid
}

func main() {
	arguments := CLIArgs{}

	flag.BoolVar(&arguments.ShowHelp, "help", false, "Show usage information")
	flag.StringVar(&arguments.ROMPath, "rom", "", "Optional. Path to game dump to scan. Not required if using -bruteforce")
	flag.StringVar(&arguments.Packet, "packet", "", "Optional. Packet to test possible access keys against. Required if using -bruteforce")
	flag.StringVar(&arguments.PreferEncoding, "prefer-encoding", "", "Optional. Reorder potential access keys to place those which use this encoding at the start of the list. Can be one of UTF8, UTF16BE, or UTF16LE. Will default to UTF16LE for 3DS .code dumps and UTF16BE for Wii U .elf dumps. Not required if using -bruteforce")
	flag.BoolVar(&arguments.Bruteforce, "bruteforce", false, "Optional. Bruteforce valid game server access keys without scanning a game dump. Valid access keys may not be the original access key. Requires -packet to be set. Will take a long time")
	flag.IntVar(&arguments.BruteforceStopAfter, "stop-after", 1, "Optional. Stop bruteforcing after finding this number of valid access keys. Defaults to 1. Setting to 0 will check all keys from 00000000-ffffffff")

	flag.Parse()

	if arguments.ShowHelp {
		flag.Usage()
		os.Exit(0)
	}

	if arguments.ROMPath == "" && !arguments.Bruteforce {
		fmt.Fprintf(os.Stderr, "Missing game dump path and not using -bruteforce\n")
		flag.Usage()
		os.Exit(0)
	}

	if arguments.Bruteforce && arguments.Packet == "" {
		fmt.Fprintf(os.Stderr, "Missing sample packet\n")
		flag.Usage()
		os.Exit(0)
	}

	if arguments.PreferEncoding != "" && arguments.PreferEncoding != "UTF8" && arguments.PreferEncoding != "UTF16BE" && arguments.PreferEncoding != "UTF16LE" {
		fmt.Fprintf(os.Stderr, "Invalid encoding type. Can only be one of UTF8, UTF16BE, or UTF16LE\n")
		flag.Usage()
		os.Exit(0)
	}

	if !arguments.Bruteforce {
		fmt.Println("Scanning game dump")
		possibleAccessKeys, err := extractPossibleAccessKey(arguments)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning game dump: %v\n", err)
			os.Exit(0)
		}

		if len(possibleAccessKeys) == 0 {
			fmt.Println("No possible access keys found")
			os.Exit(0)
		}

		if arguments.Packet != "" {
			packetData, err := hex.DecodeString(arguments.Packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding sample packet: %v\n", err)
				os.Exit(0)
			}

			fmt.Println("Checking test packet...")

			validAccessKeys := checkPacket(packetData, possibleAccessKeys)

			fmt.Printf("Found %d valid access key(s):\n", len(validAccessKeys))

			for _, validAccessKey := range validAccessKeys {
				fmt.Printf("%s\n", validAccessKey)
			}
		} else {
			for _, possibleAccessKey := range possibleAccessKeys {
				fmt.Printf("%s\n", possibleAccessKey)
			}

			fmt.Printf("No test packet provided. Found %d possible access key(s) (the correct key is usually one of the first)\n", len(possibleAccessKeys))
		}
	} else {
		validAccessKeys := bruteforce(arguments)

		if len(validAccessKeys) == 0 {
			fmt.Println("No possible access keys found. This may indicate the packet data is incorrect, the title uses a different access key format, or the title uses a different signature/checksum algorithm")
		} else {
			fmt.Printf("Found %d valid access key(s):\n", len(validAccessKeys))

			for _, validAccessKey := range validAccessKeys {
				fmt.Printf("%s\n", validAccessKey)
			}
		}
	}
}
