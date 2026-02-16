#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#import <stdlib.h>
#import "../bruteforce.h"

static id<MTLDevice> device = nil;
static id<MTLCommandQueue> queue = nil;
static id<MTLLibrary> library = nil;
static uint64_t total = 0x100000000ULL;
static uint32_t chunk_size = 0x400000;
static uint32_t print_interval = 0x10000000;
static id<MTLComputePipelineState> prudpv1_pipeline = nil;
static id<MTLComputePipelineState> prudpv0_pipeline = nil;
static NSUInteger prudpv1_threads_count = 0;
static NSUInteger prudpv0_threads_count = 0;
static BruteforceResult result;

static void initialize(void) {
	if (device != nil) {
		return;
	}

	device = MTLCreateSystemDefaultDevice();
	queue = [device newCommandQueue];

	// * Embed the Metal source here rather than import it from a file so that
	// * the compiled program doesn't have to import anything
	// TODO - Is there a way to put this in a .metal file without breaking imports?
	NSString* shader_source = @R"(
		#include <metal_stdlib>
		using namespace metal;

		constant uint32_t MD5_BLOCK_SIZE = 64;
		constant uint32_t MD5_DIGEST_SIZE = 16;
		constant uint32_t MD5_LENGTH_SIZE = 8;

		struct MD5State {
			uint32_t a0;
			uint32_t b0;
			uint32_t c0;
			uint32_t d0;
		};

		inline void pack_bytes_to_block(thread const uint8_t* bytes, uint32_t length, thread uint32_t* block) {
			for (int i = 0; i < 16; i++) {
				block[i] = 0;
			}

			for (uint32_t i = 0; i < length; i++) {
				block[i / 4] |= uint32_t(bytes[i]) << ((i % 4) * 8);
			}
		}

		inline void state_to_bytes(thread const MD5State& state, thread uint8_t* out) {
			uint32_t vals[4] = { state.a0, state.b0, state.c0, state.d0 };
			for (int i = 0; i < 4; i++) {
				out[i*4] = vals[i] & 0xFF;
				out[i*4 + 1] = (vals[i] >> 8) & 0xFF;
				out[i*4 + 2] = (vals[i] >> 16) & 0xFF;
				out[i*4 + 3] = (vals[i] >> 24) & 0xFF;
			}
		}

		constant uint32_t K[64] = {
			0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
			0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
			0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
			0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
			0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
			0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
			0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
			0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
			0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
			0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
			0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
			0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
			0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
			0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
			0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
			0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
		};

		constant uint32_t S[64] = {
			7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
			4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
		};

		inline uint32_t left_rotate(uint32_t f, uint32_t s) {
			return (f << s) | (f >> (32 - s));
		}

		inline uint32_t F(uint32_t a, uint32_t b, uint32_t c) {
			return (a & b) | (~a & c);
		}

		inline uint32_t G(uint32_t a, uint32_t b, uint32_t c) {
			return (a & c) | (b & ~c);
		}

		inline uint32_t H(uint32_t a, uint32_t b, uint32_t c) {
			return a ^ b ^ c;
		}

		inline uint32_t I(uint32_t a, uint32_t b, uint32_t c) {
			return b ^ (a | ~c);
		}

		void md5_transform(thread MD5State& state, thread const uint32_t* block) {
			uint32_t a = state.a0;
			uint32_t b = state.b0;
			uint32_t c = state.c0;
			uint32_t d = state.d0;

			for (int i = 0; i < 64; i++) {
				uint32_t f;
				uint32_t g;

				if (i < 16) {
					f = F(b, c, d);
					g = i;
				} else if (i < 32) {
					f = G(b, c, d);
					g = (5 * i + 1) % 16;
				} else if (i < 48) {
					f = H(b, c, d);
					g = (3 * i + 5) % 16;
				} else {
					f = I(b, c, d);
					g = (7 * i) % 16;
				}

				f = f + a + K[i] + block[g];
				a = d;
				d = c;
				c = b;
				b = b + left_rotate(f, S[i]);
			}

			state.a0 += a;
			state.b0 += b;
			state.c0 += c;
			state.d0 += d;
		}

		void md5_init(thread MD5State& state) {
			state.a0 = 0x67452301;
			state.b0 = 0xEFCDAB89;
			state.c0 = 0x98BADCFE;
			state.d0 = 0x10325476;
		}

		void md5_hash(thread const uint8_t* data, uint32_t length, thread uint8_t* output) {
			MD5State state;
			uint32_t block[MD5_BLOCK_SIZE / 4];
			uint32_t processed = 0;
			uint64_t total_bits = uint64_t(length) * 8;

			md5_init(state);

			while (processed + MD5_BLOCK_SIZE <= length) {
				pack_bytes_to_block(data + processed, MD5_BLOCK_SIZE, block);
				md5_transform(state, block);
				processed += MD5_BLOCK_SIZE;
			}

			uint32_t remaining = length - processed;
			pack_bytes_to_block(data + processed, remaining, block);
			block[remaining / 4] |= 0x80u << ((remaining % 4) * 8);

			if (remaining >= MD5_BLOCK_SIZE - MD5_LENGTH_SIZE) {
				md5_transform(state, block);
				for (int i = 0; i < MD5_BLOCK_SIZE / 4; i++) block[i] = 0;
			}

			block[MD5_BLOCK_SIZE / 4 - 2] = uint32_t(total_bits);
			block[MD5_BLOCK_SIZE / 4 - 1] = uint32_t(total_bits >> 32);

			md5_transform(state, block);
			state_to_bytes(state, output);
		}

		void hmac_md5(thread const uint8_t* key, uint32_t key_len, thread const uint8_t* message, uint32_t message_len, thread uint8_t* output) {
			uint8_t block_sized_key[MD5_BLOCK_SIZE];
			uint8_t i_key_pad[MD5_BLOCK_SIZE];
			uint8_t o_key_pad[MD5_BLOCK_SIZE];
			uint8_t inner_input[MD5_BLOCK_SIZE + MD5_BLOCK_SIZE];
			uint8_t outer_input[MD5_BLOCK_SIZE + MD5_DIGEST_SIZE];
			uint8_t inner_hash[MD5_DIGEST_SIZE];

			if (key_len > MD5_BLOCK_SIZE) {
				md5_hash(key, key_len, block_sized_key);
				for (int i = MD5_DIGEST_SIZE; i < MD5_BLOCK_SIZE; i++) {
					block_sized_key[i] = 0;
				}
			} else {
				for (int i = 0; i < MD5_BLOCK_SIZE; i++) {
					block_sized_key[i] = (i < key_len) ? key[i] : 0;
				}
			}

			for (int i = 0; i < MD5_BLOCK_SIZE; i++) {
				i_key_pad[i] = block_sized_key[i] ^ 0x36;
				o_key_pad[i] = block_sized_key[i] ^ 0x5c;
			}

			// * Inner hash: hash(i_key_pad || message)
			for (int i = 0; i < MD5_BLOCK_SIZE; i++) {
				inner_input[i] = i_key_pad[i];
			}

			for (uint32_t i = 0; i < message_len; i++) {
				inner_input[MD5_BLOCK_SIZE + i] = message[i];
			}

			md5_hash(inner_input, MD5_BLOCK_SIZE + message_len, inner_hash);

			// * Outer hash: hash(o_key_pad || inner_hash)
			for (int i = 0; i < MD5_BLOCK_SIZE; i++) {
				outer_input[i] = o_key_pad[i];
			}

			for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
				outer_input[MD5_BLOCK_SIZE + i] = inner_hash[i];
			}

			md5_hash(outer_input, MD5_BLOCK_SIZE + MD5_DIGEST_SIZE, output);
		}

		inline uint8_t nibble_to_hex(uint8_t n) {
			return n < 10 ? ('0' + n) : ('a' + n - 10);
		}

		void uint32_to_hex(uint32_t value, thread uint8_t* out) {
			for (int i = 7; i >= 0; i--) {
				out[i] = nibble_to_hex(value & 0xF);
				value >>= 4;
			}
		}

		void uint32_to_le_bytes(uint32_t value, thread uint8_t* out) {
			out[0] = value & 0xFF;
			out[1] = (value >> 8) & 0xFF;
			out[2] = (value >> 16) & 0xFF;
			out[3] = (value >> 24) & 0xFF;
		}

		uint32_t sum_bytes(thread const uint8_t* data, uint32_t length) {
			uint32_t sum = 0;
			for (uint32_t i = 0; i < length; i++) {
				sum += data[i];
			}
			return sum;
		}

		kernel void bruteforce_prudpv0_checksum(
			device const uint32_t& precomputed_checksum [[buffer(0)]],
			device const uint8_t& target_checksum [[buffer(1)]],
			device atomic_uint* found [[buffer(2)]],
			device uint32_t* result [[buffer(3)]],
			device const uint32_t& offset [[buffer(4)]],
			uint gid [[thread_position_in_grid]]
		) {
			uint32_t candidate = offset + gid;
			uint8_t access_key[8];

			uint32_to_hex(candidate, access_key);

			uint32_t checksum = precomputed_checksum + sum_bytes(access_key, 8);

			if ((checksum & 0xFF) == target_checksum) {
				uint32_t already_found = atomic_exchange_explicit(found, 1, memory_order_relaxed);
				if (!already_found) {
					*result = candidate;
				}
			}
		}

		kernel void bruteforce_prudpv1_hmac(
			device const uint8_t* header [[buffer(0)]],
			device const uint8_t* target_signature [[buffer(1)]],
			device const uint8_t* options_payload [[buffer(2)]],
			device const uint32_t& options_payload_len [[buffer(3)]],
			device atomic_uint* found [[buffer(4)]],
			device uint32_t* result [[buffer(5)]],
			device const uint32_t& offset [[buffer(6)]],
			uint gid [[thread_position_in_grid]]
		) {
			uint32_t candidate = offset + gid;
			uint8_t access_key[8];
			uint8_t access_key_sum_bytes[4];
			uint8_t md5_key[MD5_DIGEST_SIZE];
			uint8_t message[64];
			uint32_t message_index = 0;
			uint8_t computed_sig[MD5_DIGEST_SIZE];

			uint32_to_hex(candidate, access_key);

			uint32_t access_key_sum = sum_bytes(access_key, 8);

			uint32_to_le_bytes(access_key_sum, access_key_sum_bytes);

			md5_hash(access_key, 8, md5_key);

			for (int i = 0; i < 8; i++) {
				message[message_index++] = header[i];
			}

			for (int i = 0; i < 4; i++) {
				message[message_index++] = access_key_sum_bytes[i];
			}

			for (uint32_t i = 0; i < options_payload_len && message_index < 56; i++) {
				message[message_index++] = options_payload[i];
			}

			hmac_md5(md5_key, MD5_DIGEST_SIZE, message, message_index, computed_sig);

			bool match = true;
			for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
				if (computed_sig[i] != target_signature[i]) {
					match = false;
					break;
				}
			}

			if (match) {
				uint32_t already_found = atomic_exchange_explicit(found, 1, memory_order_relaxed);
				if (!already_found) {
					*result = candidate;
				}
			}
		}
	)";

	NSError* error = nil;

	library = [device newLibraryWithSource:shader_source options:nil error:&error];
	if (error) {
		NSLog(@"Failed to compile shader: %@", error);
		return;
	}

	id<MTLFunction> prudpv0_function = [library newFunctionWithName:@"bruteforce_prudpv0_checksum"];
	prudpv0_pipeline = [device newComputePipelineStateWithFunction:prudpv0_function error:&error];
	if (error) {
		NSLog(@"Failed to create prudpv0 pipeline: %@", error);
		return;
	}

	id<MTLFunction> prudpv1_function = [library newFunctionWithName:@"bruteforce_prudpv1_hmac"];
	prudpv1_pipeline = [device newComputePipelineStateWithFunction:prudpv1_function error:&error];
	if (error) {
		NSLog(@"Failed to create prudpv1 pipeline: %@", error);
		return;
	}

	prudpv0_threads_count = MIN(prudpv0_pipeline.maxTotalThreadsPerThreadgroup, 256);
	prudpv1_threads_count = MIN(prudpv1_pipeline.maxTotalThreadsPerThreadgroup, 256);

	result.found = false;
	result.value = 0;
}

BruteforceResult bruteforce_prudpv0_checksum(const uint8_t* data, const uint32_t data_length, const uint8_t target_checksum) {
	@autoreleasepool {
		initialize();

		uint32_t word_count = data_length / 4;
		uint32_t temp = 0;
		uint32_t aligned_offset = data_length & ~3;
		uint32_t precomputed_checksum = 0;

		for (uint32_t i = 0; i < word_count; i++) {
			temp += (uint32_t)data[i * 4] | ((uint32_t)data[i * 4 + 1] << 8) | ((uint32_t)data[i * 4 + 2] << 16) | ((uint32_t)data[i * 4 + 3] << 24);
		}

		for (uint32_t i = aligned_offset; i < data_length; i++) {
			precomputed_checksum += data[i];
		}

		precomputed_checksum += (temp & 0xFF) + ((temp >> 8) & 0xFF) + ((temp >> 16) & 0xFF) + ((temp >> 24) & 0xFF);

		id<MTLBuffer> precomputed_checksum_buffer = [device newBufferWithBytes:&precomputed_checksum length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
		id<MTLBuffer> target_checksum_buffer = [device newBufferWithBytes:&target_checksum length:sizeof(uint8_t) options:MTLResourceStorageModeShared];

		id<MTLBuffer> found_buffer = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
		id<MTLBuffer> result_buffer = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
		id<MTLBuffer> offset_buffer = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];

		for (uint64_t offset = 0; offset < total; offset += chunk_size) {
			uint32_t current_offset = (uint32_t)offset;
			memcpy(offset_buffer.contents, &current_offset, sizeof(uint32_t));

			id<MTLCommandBuffer> command_buffer = [queue commandBuffer];
			id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];

			[encoder setComputePipelineState:prudpv0_pipeline];
			[encoder setBuffer:precomputed_checksum_buffer offset:0 atIndex:0];
			[encoder setBuffer:target_checksum_buffer offset:0 atIndex:1];
			[encoder setBuffer:found_buffer offset:0 atIndex:2];
			[encoder setBuffer:result_buffer offset:0 atIndex:3];
			[encoder setBuffer:offset_buffer offset:0 atIndex:4];

			[encoder dispatchThreads:MTLSizeMake(MIN(chunk_size, total - offset), 1, 1) threadsPerThreadgroup:MTLSizeMake(prudpv1_threads_count, 1, 1)];
			[encoder endEncoding];

			[command_buffer commit];
			[command_buffer waitUntilCompleted];

			uint32_t found = *(uint32_t*)found_buffer.contents;
			if (found) {
				printf("\rProgress: 100.0%%\n");

				result.found = true;
				result.value = *(uint32_t*)result_buffer.contents;

				return result;
			}

			if (offset % print_interval == 0) {
				printf("\rProgress: %.1f%%", (double)offset / total * 100);
				fflush(stdout);
			}
		}

		printf("\rProgress: 100.0%%\n");

		return result;
	}
}

BruteforceResult bruteforce_prudpv1_hmac(const uint8_t* header, const uint8_t* target_signature, const uint8_t* options_payload, uint32_t options_payload_length) {
	@autoreleasepool {
		initialize();

		id<MTLBuffer> header_buffer = [device newBufferWithBytes:header length:8 options:MTLResourceStorageModeShared];
		id<MTLBuffer> target_signature_buffer = [device newBufferWithBytes:target_signature length:16 options:MTLResourceStorageModeShared];
		id<MTLBuffer> payload_buffer = [device newBufferWithBytes:options_payload length:options_payload_length options:MTLResourceStorageModeShared];
		id<MTLBuffer> payload_length_buffer = [device newBufferWithBytes:&options_payload_length length:sizeof(uint32_t) options:MTLResourceStorageModeShared];

		id<MTLBuffer> found_buffer = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
		id<MTLBuffer> result_buffer = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
		id<MTLBuffer> offset_buffer = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];

		for (uint64_t offset = 0; offset < total; offset += chunk_size) {
			uint32_t current_offset = (uint32_t)offset;
			memcpy(offset_buffer.contents, &current_offset, sizeof(uint32_t));

			id<MTLCommandBuffer> command_buffer = [queue commandBuffer];
			id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];

			[encoder setComputePipelineState:prudpv1_pipeline];
			[encoder setBuffer:header_buffer offset:0 atIndex:0];
			[encoder setBuffer:target_signature_buffer offset:0 atIndex:1];
			[encoder setBuffer:payload_buffer offset:0 atIndex:2];
			[encoder setBuffer:payload_length_buffer offset:0 atIndex:3];
			[encoder setBuffer:found_buffer offset:0 atIndex:4];
			[encoder setBuffer:result_buffer offset:0 atIndex:5];
			[encoder setBuffer:offset_buffer offset:0 atIndex:6];

			[encoder dispatchThreads:MTLSizeMake(MIN(chunk_size, total - offset), 1, 1) threadsPerThreadgroup:MTLSizeMake(prudpv1_threads_count, 1, 1)];
			[encoder endEncoding];

			[command_buffer commit];
			[command_buffer waitUntilCompleted];

			uint32_t found = *(uint32_t*)found_buffer.contents;
			if (found) {
				printf("\rProgress: 100.0%%\n");

				result.found = true;
				result.value = *(uint32_t*)result_buffer.contents;

				return result;
			}

			if (offset % print_interval == 0) {
				printf("\rProgress: %.1f%%", (double)offset / total * 100);
				fflush(stdout);
			}
		}

		printf("\rProgress: 100.0%%\n");

		return result;
	}
}
