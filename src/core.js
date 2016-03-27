import Base58 from 'bs58';
import nacl from 'tweetnacl-rn';
import base64 from 'base64-js';
import RIPEMD160 from './libs/ripemd160';
import sha256 from './libs/sha256';
import {
	doubleSha256,
	appendBuffer,
	int32ToBytes,
	stringtoUTF8Array,
	utf8ArrayToStr,
	equal
} from './utils';


export function encrypt(msg, password) {
	return Base58.encode(nacl.secretbox(stringtoUTF8Array(msg), base64.toByteArray('crkCCNKADjatFscwlBoDjXw62dhwMNMp'), new Uint8Array(doubleSha256(password))));
}


export function decrypt(hash, password) {
	hash = Base58.decode(hash);
	return utf8ArrayToStr(nacl.secretbox.open(new Uint8Array(hash), base64.toByteArray('crkCCNKADjatFscwlBoDjXw62dhwMNMp'), new Uint8Array(doubleSha256(password))));
}


export function getAccountAddressType(address) {
	try {
		const ADDRESS_VERSION = 58;  // Q
		const AT_ADDRESS_VERSION = 23; // A

		if (typeof(address) == "string") {
			address = new Uint8Array(Base58.decode(address));
		}

		var checkSum = address.subarray(address.length - 4, address.length)
		var addressWithoutChecksum = address.subarray(0, address.length - 4);

		var checkSumTwo = doubleSha256(addressWithoutChecksum);
		checkSumTwo = checkSumTwo.subarray(0, 4);

		if (equal(checkSum, checkSumTwo)) {
			if (address[0] == ADDRESS_VERSION) {
				return "standard";
			}
			if (address[0] == AT_ADDRESS_VERSION) {
				return "at";
			}
		}

		return "invalid";

	} catch (e) {
		return "invalid";
	}
}


export function isValidAddress(address) {
	return (getAccountAddressType(address) != "invalid");
}


export function generateSeedByPassword(password) {
	if (typeof(password) !== 'string') {
		throw 'password should be string';
	}
	if (password.length < 8) {
		throw 'invalid passphrase';
	}

	let byteSeed = new Uint8Array(doubleSha256(password));
	return Base58.encode(byteSeed);
}


export function generateAccountFromSeed(base58AccountSeed) {
	if (Base58.decode(base58AccountSeed).length != 32) {
		throw 'invalid seed';
	}
	let keyPair = getKeyPairFromSeed(base58AccountSeed, false);
	let base58AccountAddress = getAccountAddressFromPublicKey(keyPair.publicKey);
	let base58AccountPublicKey = Base58.encode(keyPair.publicKey);
	let base58AccountPrivateKey = Base58.encode(keyPair.privateKey);
	return {
		address: base58AccountAddress,
		publicKey: base58AccountPublicKey,
		privateKey: base58AccountPrivateKey
	}
}


export function generateAccounts(base58BaseSeed, count = 2) {
	let seed = Base58.decode(base58BaseSeed);
	if (seed.length !== 32) {
		throw 'invalid seed';
	}
	let accounts = [];
	for (let i = 0; i < count; i++) {
		let base58AccountSeed = generateAccountSeed(seed, i, true);
		accounts.push(generateAccountFromSeed(base58AccountSeed))
	}
	return accounts;
}


export function getKeyPairFromSeed(seed, returnBase58) {
	if (typeof(seed) == "string") {
		seed = Base58.decode(seed);
	}

	let keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));


	if (returnBase58) {
		return {
			privateKey: Base58.encode(keyPair.secretKey),
			publicKey: Base58.encode(keyPair.publicKey)
		};
	} else {
		return {
			privateKey: keyPair.secretKey,
			publicKey: keyPair.publicKey
		};
	}
}


export function generateAccountSeed(seed, nonce, returnBase58) {
	if (typeof(seed) == "string") {
		seed = Base58.decode(seed);
	}

	let nonceBytes = int32ToBytes(nonce);

	let resultSeed = new Uint8Array(nonceBytes);
	resultSeed = appendBuffer(resultSeed, seed);
	resultSeed = appendBuffer(resultSeed, nonceBytes);

	if (returnBase58) {
		return Base58.encode(new Uint8Array(doubleSha256(resultSeed)));
	} else {
		return new Uint8Array(doubleSha256(resultSeed));
	}
}


export function getAccountAddressFromPublicKey(publicKey) {
	const ADDRESS_VERSION = 58;


	if (typeof(publicKey) == "string") {
		publicKey = new Uint8Array(Base58.decode(publicKey));
	}

	var ripemd160 = new RIPEMD160();

	let publicKeyHashSHA256 = sha256.digest(publicKey);
	let publicKeyHash = ripemd160.digest([].slice.call(publicKeyHashSHA256));
	let addressArray = new Uint8Array([ADDRESS_VERSION]);
	addressArray = appendBuffer(addressArray, publicKeyHash);

	let checkSum = doubleSha256(addressArray);
	addressArray = appendBuffer(addressArray, checkSum.subarray(0, 4));
	return Base58.encode(addressArray);
}
