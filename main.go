package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"unicode/utf16"

	"github.com/PretendoNetwork/nex-go/v2"
)

const (
	CHUNK_SIZE         = 64 * 1024 // * 64k chunks seems fine?
	CHUNK_OVERLAP_SIZE = 16        // * Size of an 8 character UTF16 string
	UTF8_CHAR_WIDTH    = 1
	UTF16_CHAR_WIDTH   = 2
)

func extractHexStrings(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	possibleAccessKeys := make([]string, 0)
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

	possibleAccessKeysFiltered := make([]string, 0)

	for _, possibleAccessKey := range possibleAccessKeys {
		if !slices.Contains(possibleAccessKeysFiltered, possibleAccessKey) {
			possibleAccessKeysFiltered = append(possibleAccessKeysFiltered, possibleAccessKey)
		}
	}

	return possibleAccessKeysFiltered, nil
}

func extractPossibleAccessKeys(chunk []byte, charWidth int, order binary.ByteOrder) []string {
	possibleAccessKeys := make([]string, 0)
	stringBuffer := make([]uint16, 0, 8)

	checkStringBuffer := func() {
		if len(stringBuffer) == 8 {
			if charWidth == 1 {
				bytes := make([]byte, 8)
				for j, u16 := range stringBuffer {
					bytes[j] = byte(u16)
				}

				possibleAccessKeys = append(possibleAccessKeys, string(bytes))
			} else {
				possibleAccessKeys = append(possibleAccessKeys, string(utf16.Decode(stringBuffer)))
			}
		}
	}

	for i := 0; i < len(chunk); i += charWidth {
		var char uint16

		if charWidth == 1 {
			char = uint16(chunk[i])
		} else {
			char = order.Uint16(chunk[i:])
		}

		if char <= 0x7F && isLowercaseHex(byte(char)) {
			stringBuffer = append(stringBuffer, char)
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

			valid := false
			server := nex.NewPRUDPServer()
			readStream := nex.NewByteStreamIn(packetData, nil, nil)

			server.AccessKey = possibleAccessKey

			if bytes.Equal(packetData[:2], []byte{0xEA, 0xD0}) {
				packet, err := nex.NewPRUDPPacketV1(server, nil, readStream)
				if err != nil {
					return
				}

				// * HACK - nex-go doesn't have a way to check the v1 signature directly,
				// *        so just re-encode the packet directly and check if it matches
				packet.SetSignature(packet.CalculateSignature(nil, nil))

				valid = bytes.Equal(packetData, packet.Bytes())
			} else {
				_, err := nex.NewPRUDPPacketV0(server, nil, readStream)
				valid = err == nil // * The v0 decoder validates the checksum for us
			}

			if valid {
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
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <rom-path> [test-packet]\n", os.Args[0])
		os.Exit(0)
	}

	possibleAccessKeys, err := extractHexStrings(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(0)
	}

	if len(possibleAccessKeys) == 0 {
		fmt.Println("No possible access keys found")
		os.Exit(0)
	}

	if len(os.Args) == 3 {
		packetData, err := hex.DecodeString(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
}
