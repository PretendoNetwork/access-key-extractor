const fs = require('node:fs');
const crypto = require('node:crypto');
const args = process.argv.slice(2);

const REGEX_UTF16 = /\0([a-f0-9]\0){8}/g;
const REGEX_UTF8 = /\0([a-f0-9]){8}/g;

// Check CLI args
const romPath = args[0];
const testPacket = args[1];

if (!romPath || romPath.trim() === '') {
	console.log('Usage:\nnode extractor.js <path> [packet]');

	return;
}

// Start timer
console.time('Parsing rom for access keys');

// Read the ROM contents
const romBuffer = fs.readFileSync(romPath);
const romContents = romBuffer.toString('latin1');

// Extract possible keys
let utf16Matches = romContents.match(REGEX_UTF16);
let utf8Matches = romContents.match(REGEX_UTF8);

let possibleKeys = [];

if (utf16Matches) {
	possibleKeys = [...utf16Matches];
}

if (utf8Matches) {
	possibleKeys = [...possibleKeys, ...utf8Matches];
}

possibleKeys = possibleKeys.map(match => Buffer.from(match).toString().replace(/\0/g, ''));
possibleKeys = [...new Set(possibleKeys)];

if (!possibleKeys || possibleKeys.length === 0) {
	console.timeEnd('Parsing rom for access keys');

	console.log('No possible access keys found');

	return;
}

// If no test packet was provided, just exit here
if (!testPacket) {
	console.timeEnd('Parsing rom for access keys');

	console.log('No test packet found');
	console.log('Possible access keys (the correct key is usually one of the first)');
	console.log(possibleKeys);

	return;
}

const MAGIC_V1 = Buffer.from([0xEA, 0xD0]);

const packetBuffer = Buffer.from(testPacket, 'hex');

if (MAGIC_V1.equals(packetBuffer.subarray(0, 2))) {
	checkPacketV1();
} else {
	checkPacketV0();
}

// Decode the packet as PRUDPv0 and check the signature
function checkPacketV0() {
	// Grab original checksum
	oldcheck = Buffer.from([packetBuffer[packetBuffer.length - 1]]);

	// Loop over all possible keys and calculate the checksum with the given key
	for (const possibleKey of possibleKeys) {
		console.log("Trying key: " + possibleKey);
		newcheck = calc_checksum(possibleKey, packetBuffer.slice(0, packetBuffer.length - 1));

		// If a match is found, output the key and kill the loop
		if(oldcheck.equals(Buffer.from([newcheck]))) {
			console.timeEnd('Parsing rom for access keys');
			console.log(`Found working access key: ${possibleKey}`);
			return;
		}
	}
	console.timeEnd('Parsing rom for access keys');

	console.log('No possible access keys found for provided test packet. Was the test packet sent from the provided title?');
}

// Calculate V0 checksum (grabbed from https://github.com/andreluis034/prudp/blob/master/libs/Packets/PRUDPPacketVersion0.js, with slight modifications)
function calc_checksum(key, buffer) {
	let number = 0;
	if(typeof key === 'string') {
		key = Buffer.from(key);
	} 
	if (key instanceof Buffer) {
		key = key.reduce((a, b) => { return a + b; });
	}
	if(typeof key === 'number') {
		number = key & 0xFF;
	} else {
		throw new Error('Invalid key format to create checksum');
	}
	const length = buffer.length;
	const tuple = [];
	let pos = 0;
	let sum = 0;
	const words = Math.floor(length/4);
	for (let i = 0; i < Math.floor(length/4); i++) {
		sum += buffer.readUInt32LE(i * 4, true);
	}
	sum = (sum & 0xFFFFFFFF) >>> 0;
	for(let i = words * 4; i < length; ++i) {
		key += buffer.readUInt8(i);
	}
	
	
	const buff = Buffer.alloc(4);
	buff.writeUInt32LE(sum, 0);
	key += buff.reduce((a, b) => { return a + b; });
	return (key & 0xFF) >>> 0;
}

// Decode the packet as PRUDPv1 and check the signature
function checkPacketV1() {
	// Unpack parts of the packet header
	const header = packetBuffer.subarray(2, 14);
	const expectedSignature = packetBuffer.subarray(14, 30);
	const optionsSize = header.readUInt8(1);

	// Extract required data from the packet
	const headerSection = header.subarray(4);
	const options = packetBuffer.subarray(30, 30 + optionsSize);

	// Loop over all possible keys and calculate the signature with the given key
	for (const possibleKey of possibleKeys) {
		console.log("Trying key: " + possibleKey);
		const keyBuffer = Buffer.from(possibleKey);
		const signatureKey = md5(possibleKey);
		const signatureBase = keyBuffer.reduce((sum, byte) => sum + byte, 0);
		const signatureBaseBuffer = Buffer.alloc(4);
		signatureBaseBuffer.writeUInt32LE(signatureBase);

		const hmac = crypto.createHmac('md5', signatureKey);

		hmac.update(headerSection);
		hmac.update(Buffer.alloc(0)); // session key not present in SYN packet
		hmac.update(signatureBaseBuffer);
		hmac.update(Buffer.alloc(0)); // connection signature not present in SYN packet
		hmac.update(options);
		hmac.update(Buffer.alloc(0)); // payload not present in SYN packet

		const calculatedSignature = hmac.digest();

		// If a match is found, output the key and kill the loop
		if (expectedSignature.equals(calculatedSignature)) {
			console.timeEnd('Parsing rom for access keys');
			console.log(`Found working access key: ${possibleKey}`);
			return;
		}
	}

	// If the loop was not killed, assume no valid keys were found
	// THIS MAY ONLY MEAN AN INCORRECT PACKET WAS PROVIDED
	console.timeEnd('Parsing rom for access keys');

	console.log('No possible access keys found for provided test packet. Was the test packet sent from the provided title?');
}

function md5(text) {
	return crypto.createHash('md5').update(text).digest();
}