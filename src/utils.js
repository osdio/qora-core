import Base58 from 'bs58';
import nacl from 'tweetnacl';
import sha256 from './libs/sha256';
import TYPES from './constaints/transactionTypes';

export function utf8ArrayToStr(array) {
	var out, i, len, c;
	var char2, char3;

	out = "";
	len = array.length;
	i = 0;
	while(i < len) {
		c = array[i++];
		switch(c >> 4)
		{
			case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
			// 0xxxxxxx
			out += String.fromCharCode(c);
			break;
			case 12: case 13:
			// 110x xxxx   10xx xxxx
			char2 = array[i++];
			out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
			break;
			case 14:
				// 1110 xxxx  10xx xxxx  10xx xxxx
				char2 = array[i++];
				char3 = array[i++];
				out += String.fromCharCode(((c & 0x0F) << 12) |
					((char2 & 0x3F) << 6) |
					((char3 & 0x3F) << 0));
				break;
		}
	}

	return out;
}


export function stringtoUTF8Array(message) {
	if (typeof message == 'string') {
		var s = unescape(encodeURIComponent(message)); // UTF-8
		message = new Uint8Array(s.length);
		for (var i = 0; i < s.length; i++) {
			message[i] = s.charCodeAt(i) & 0xff;
		}
	}
	return message;
}


export function int32ToBytes(word) {
	var byteArray = [];
	for (var b = 0; b < 32; b += 8) {
		byteArray.push((word >>> (24 - b % 32)) & 0xFF);
	}
	return byteArray;
}


export function appendBuffer(buffer1, buffer2) {
	buffer1 = new Uint8Array(buffer1);
	buffer2 = new Uint8Array(buffer2);
	var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
	tmp.set(buffer1, 0);
	tmp.set(buffer2, buffer1.byteLength);
	return tmp;
}


export function doubleSha256(str) {
	return sha256.digest(sha256.digest(str));
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


export function generatePaymentTransactionBase(publicKey, lastReference, recipient, amount, fee, timestamp) {
	const txType = TYPES.PAYMENT_TRANSACTION;
	const typeBytes = int32ToBytes(txType);
	const timestampBytes = int64ToBytes(timestamp);
	const amountBytes = int64ToBytes(amount * 100000000);
	const feeBytes = int64ToBytes(fee * 100000000);

	let data = new Uint8Array();

	data = appendBuffer(data, typeBytes);
	data = appendBuffer(data, timestampBytes);
	data = appendBuffer(data, lastReference);
	data = appendBuffer(data, publicKey);
	data = appendBuffer(data, recipient);
	data = appendBuffer(data, amountBytes);
	data = appendBuffer(data, feeBytes);

	return data;
}


export function generateArbitraryTransactionV3Base(publicKey, lastReference, service, arbitraryData, fee, timestamp) {
	const txType = TYPES.ARBITRARY_TRANSACTION;
	const typeBytes = int32ToBytes(txType);
	const timestampBytes = int64ToBytes(timestamp);
	const feeBytes = int64ToBytes(fee * 100000000);
	const serviceBytes = int32ToBytes(service);
	const dataSizeBytes = int32ToBytes(arbitraryData.length);
	const paymentsLengthBytes = int32ToBytes(0);  // Support payments - not yet.

	var data = new Uint8Array();


	data = appendBuffer(data, typeBytes);
	data = appendBuffer(data, timestampBytes);
	data = appendBuffer(data, lastReference);
	data = appendBuffer(data, publicKey);
	data = appendBuffer(data, paymentsLengthBytes);
	// Here it is necessary to insert the payments, if there are
	data = appendBuffer(data, serviceBytes);
	data = appendBuffer(data, dataSizeBytes);
	data = appendBuffer(data, arbitraryData);
	data = appendBuffer(data, feeBytes);


	return data;
}


export function generateRegisterNameTransactionBase(publicKey, lastReference, owner, name, value, fee, timestamp) {
	const txType = TYPES.REGISTER_NAME_TRANSACTION;
	const typeBytes = int32ToBytes(txType);
	const timestampBytes = int64ToBytes(timestamp);
	const feeBytes = int64ToBytes(fee * 100000000);
	const nameSizeBytes = int32ToBytes(name.length);
	const valueSizeBytes = int32ToBytes(value.length);

	var data = new Uint8Array();

	data = appendBuffer(data, typeBytes);
	data = appendBuffer(data, timestampBytes);
	data = appendBuffer(data, lastReference);
	data = appendBuffer(data, publicKey);
	data = appendBuffer(data, owner);
	data = appendBuffer(data, nameSizeBytes);
	data = appendBuffer(data, name);
	data = appendBuffer(data, valueSizeBytes);
	data = appendBuffer(data, value);
	data = appendBuffer(data, feeBytes);

	return data;
}
