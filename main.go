package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"main/bruteforce"
	"main/common"
	types "main/common"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"unicode/utf16"
)

const (
	CHUNK_SIZE         = 64 * 1024 // * 64k chunks seems fine?
	CHUNK_OVERLAP_SIZE = 16        // * Size of an 8 character UTF16 string
	UTF8_CHAR_WIDTH    = 1
	UTF16_CHAR_WIDTH   = 2
)

type cliArgs struct {
	showHelp                 bool
	romPath                  string
	packet                   string
	preferEncoding           string
	bruteforce               bool
	bruteforceGoroutineCount int
	gpu                      bool
}

func (c cliArgs) ShowHelp() bool {
	return c.showHelp
}

func (c cliArgs) ROMPath() string {
	return c.romPath
}

func (c cliArgs) Packet() string {
	return c.packet
}

func (c cliArgs) PreferEncoding() string {
	return c.preferEncoding
}

func (c cliArgs) Bruteforce() bool {
	return c.bruteforce
}

func (c cliArgs) BruteforceGoroutineCount() int {
	return c.bruteforceGoroutineCount
}

func (c cliArgs) GPU() bool {
	return c.gpu
}

type PossibleAccessKey struct {
	Value          string
	Encoding       string
	NULLTerminated bool
}

func extractPossibleAccessKey(arguments types.CLIArgs) ([]string, error) {
	file, err := os.Open(arguments.ROMPath())
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

	fileExtension := filepath.Ext(arguments.ROMPath())
	preferEncoding := "UTF8"

	if fileExtension == ".code" {
		// * Assume 3DS dump
		preferEncoding = "UTF16LE"
	} else if fileExtension == ".elf" {
		// * Assume Wii U dump
		preferEncoding = "UTF16BE"
	}

	if arguments.PreferEncoding() != "" {
		preferEncoding = arguments.PreferEncoding()
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

	var accessKeyValidator func(packetData []byte, possibleAccessKey string) bool

	// * Slimmed down implementations of defaultPRUDPv1CalculateSignature and defaultPRUDPv0CalculateChecksum.
	// * Assuming NEX SYN client->server packet
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

	for _, possibleAccessKey := range possibleAccessKeys {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if accessKeyValidator(packetData, possibleAccessKey) {
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

func main() {
	arguments := cliArgs{}

	flag.BoolVar(&arguments.showHelp, "help", false, "Show usage information")
	flag.StringVar(&arguments.romPath, "rom", "", "Optional. Path to game dump to scan. Not required if using -bruteforce")
	flag.StringVar(&arguments.packet, "packet", "", "Optional. Packet to test possible access keys against. Required if using -bruteforce")
	flag.StringVar(&arguments.preferEncoding, "prefer-encoding", "", "Optional. Reorder potential access keys to place those which use this encoding at the start of the list. Can be one of UTF8, UTF16BE, or UTF16LE. Will default to UTF16LE for 3DS .code dumps and UTF16BE for Wii U .elf dumps. Not required if using -bruteforce")
	flag.BoolVar(&arguments.bruteforce, "bruteforce", false, "Optional. Bruteforce valid game server access keys without scanning a game dump. Valid access keys may not be the original access key. Requires -packet to be set. Will take a long time")
	flag.IntVar(&arguments.bruteforceGoroutineCount, "threads", 0, "Optional. Number of goroutines to use during bruteforce searching. Defaults to runtime.NumCPU(). Setting this higher than your CPU core count may result in slowdowns")
	flag.BoolVar(&arguments.gpu, "gpu", false, "Optional. GPU backend to use with -bruteforce (e.g., metal, nvidia, cuda). If set without a value, auto-detects GPU. If not set, bruteforcing is done on the CPU")

	flag.Parse()

	if arguments.showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if arguments.romPath == "" && !arguments.bruteforce {
		fmt.Fprintf(os.Stderr, "Missing game dump path and not using -bruteforce\n")
		flag.Usage()
		os.Exit(0)
	}

	if arguments.bruteforce && arguments.packet == "" {
		fmt.Fprintf(os.Stderr, "Missing sample packet\n")
		flag.Usage()
		os.Exit(0)
	}

	if arguments.preferEncoding != "" && arguments.preferEncoding != "UTF8" && arguments.preferEncoding != "UTF16BE" && arguments.preferEncoding != "UTF16LE" {
		fmt.Fprintf(os.Stderr, "Invalid encoding type. Can only be one of UTF8, UTF16BE, or UTF16LE\n")
		flag.Usage()
		os.Exit(0)
	}

	if !arguments.bruteforce {
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

		if arguments.packet != "" {
			packetData, err := hex.DecodeString(arguments.packet)
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
		var result bruteforce.BruteforceResultGPU
		var backend bruteforce.Backend
		isV0 := false

		if !arguments.gpu {
			backend = bruteforce.GetCPUBackend()
		} else {
			backend = bruteforce.GetBackend()
		}

		packetData, err := hex.DecodeString(arguments.Packet())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding sample packet: %v\n", err)
			os.Exit(0)
		}

		fmt.Printf("Using %s backend\n", backend.Name())

		if bytes.Equal(packetData[:2], []byte{0xEA, 0xD0}) {
			result = backend.BruteforceV1HMAC(arguments)
		} else {
			isV0 = true
			result = backend.BruteforceV0Checksum(arguments)
		}

		if !result.Found {
			fmt.Println("No possible access keys found. This may indicate the packet data is incorrect, the title uses a different access key format, or the title uses a different signature/checksum algorithm")
		} else {
			if isV0 {
				fmt.Printf("Found valid game server access key (cannot determine if this is the original game server access key): %s\n", result.Value)
			} else {
				fmt.Printf("Found original game server access key: %s\n", result.Value)
			}
		}
	}
}
