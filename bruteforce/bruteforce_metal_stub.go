//go:build !darwin

package bruteforce

func GetMetalBackend() Backend {
	return nil
}
