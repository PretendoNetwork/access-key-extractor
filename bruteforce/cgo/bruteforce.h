#ifndef BRUTEFORCE_H
#define BRUTEFORCE_H

// * Common API for all backends to share

#include <stdint.h>
#include <stdbool.h>

typedef struct {
	bool found;
	uint32_t value;
} BruteforceResult;

BruteforceResult bruteforce_prudpv0_checksum(const uint8_t* data, const uint32_t data_length, const uint8_t target_checksum);
BruteforceResult bruteforce_prudpv1_hmac(const uint8_t* header, const uint8_t* target_signature, const uint8_t* options_payload, uint32_t options_payload_length);

#endif
