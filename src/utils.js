import Base58 from 'bs58';
import sha256 from './sha256';


export function doubleSha256(str) {
	return sha256.digest(sha256.digest(str));
}


export function wordToBytes(word) {
	let bytes = [];
	for (let b = 0; b < 32; b += 8) {
		bytes.push((word >>> (24 - b % 32)) & 0xFF);
	}
	return bytes;
}


export function int64ToBytes(int64) {
	var byteArray = [0, 0, 0, 0, 0, 0, 0, 0];

	for (let index = 0; index < byteArray.length; index++) {
		let byte = int64 & 0xff;
		byteArray [byteArray.length - index - 1] = byte;
		int64 = (int64 - byte) / 256;
	}

	return byteArray;
}


export function getTransitionStr(keyPair, lastReference, recipient, amount, fee, timestamp) {
	const PAYMENT_TRANSACTION = 2;
	let data = [];
	let typeBytes = wordToBytes(PAYMENT_TRANSACTION);
	let timestampBytes = int64ToBytes(timestamp);
	let amountBytes = int64ToBytes(amount * 100000000);
	let feeBytes = int64ToBytes(fee * 100000000);


	return data
		.concat(typeBytes)
		.concat(timestampBytes)
		.concat(Array.prototype.slice.call(lastReference))
		.concat(Array.prototype.slice.call(keyPair.publicKey))
		.concat(Array.prototype.slice.call(recipient))
		.concat(amountBytes)
		.concat(feeBytes);
}
