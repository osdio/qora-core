import Base58 from 'bs58';
import nacl_factory from 'js-nacl';
import RIPEMD160 from './ripemd160';

import sha256 from './sha256';
import { doubleSha256, getTransitionStr, wordToBytes } from './utils';


const nacl = nacl_factory.instantiate();


export function genSeedByPassword(password) {
	if (typeof(password) !== 'string') {
		throw 'password should be string';
	}
	if (password.length < 8) {
		throw 'invalid passphrase';
	}

	let byteSeed = new Uint8Array(doubleSha256(password));
	let base58BaseSeed = Base58.encode(byteSeed);
	return base58BaseSeed;
}


export function genAccountFromSeed(base58AccountSeed) {
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


export function genAccounts(base58BaseSeed, count = 2) {
	let seed = Base58.decode(base58BaseSeed);
	if (seed.length !== 32) {
		throw 'invalid seed';
	}
	let accounts = [];
	for (let i = 0; i < count; i++) {
		let base58AccountSeed = generateAccountSeed(seed, i, true);
		accounts.push(genAccountFromSeed(base58AccountSeed))
	}
	return accounts;
}


export function getKeyPairFromSeed(seed, returnBase58) {
	if (typeof(seed) == "string") {
		seed = new Uint8Array(Base58.decode(seed));
	}

	let keyPair = nacl.crypto_sign_keypair_from_seed(seed);

	if (returnBase58) {
		return {
			privateKey: Base58.encode(keyPair.signSk),
			publicKey: Base58.encode(keyPair.signPk)
		};
	} else {
		return {
			privateKey: keyPair.signSk,
			publicKey: keyPair.signPk
		};
	}
}


export function generateAccountSeed(seed, nonce, returnBase58) {
	if (typeof(seed) == "string") {
		seed = Base58.decode(seed);
	}

	let nonceBytes = wordToBytes(nonce);

	let resultSeed = []
		.concat(nonceBytes)
		.concat(Array.prototype.slice.call(seed))
		.concat(nonceBytes);

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
	let addressArray = [];
	addressArray.push(ADDRESS_VERSION);
	addressArray = addressArray.concat([].slice.call(publicKeyHash));
	let checkSum = doubleSha256(addressArray);
	addressArray.push(checkSum[0]);
	addressArray.push(checkSum[1]);
	addressArray.push(checkSum[2]);
	addressArray.push(checkSum[3]);
	return Base58.encode(new Uint8Array(addressArray));
}


export function generateSignaturePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp) {
	const data = getTransitionStr(keyPair, lastReference, recipient, amount, fee, timestamp);
	return nacl.crypto_sign_detached(new Uint8Array(data), keyPair.privateKey);
}


export function generatePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp, signature) {
	return getTransitionStr(keyPair, lastReference, recipient, amount, fee, timestamp)
		.concat(Array.prototype.slice.call(signature));
}
