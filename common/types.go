package common

type CLIArgs interface {
	ShowHelp() bool
	ROMPath() string
	Packet() string
	PreferEncoding() string
	Bruteforce() bool
	BruteforceGoroutineCount() int
	GPU() bool
}
