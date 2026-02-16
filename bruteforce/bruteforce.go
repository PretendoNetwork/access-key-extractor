package bruteforce

import (
	types "main/common"
)

type BruteforceResultGPU struct {
	Found bool
	Value string
}

type Backend interface {
	Name() string
	Available() bool
	BruteforceV0Checksum(arguments types.CLIArgs) BruteforceResultGPU
	BruteforceV1HMAC(arguments types.CLIArgs) BruteforceResultGPU
}

func GetBackend() Backend {
	if b := GetMetalBackend(); b != nil && b.Available() {
		return b
	}

	// TODO - Other platforms/GPUs

	return GetCPUBackend()
}
