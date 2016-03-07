import Base58 from 'bs58';
import nacl from 'tweetnacl';
import {
	doubleSha256,
	appendBuffer,
	int32ToBytes,
	generateArbitraryTransactionV3Base,
	generateRegisterNameTransactionBase,
	generatePaymentTransactionBase,
	stringtoUTF8Array
} from './utils';
import * as core from './core';


/*
 *
 * Simple Payment
 *
 * */
export function generateSignaturePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp) {
	const data = generatePaymentTransactionBase(keyPair.publicKey, lastReference, recipient, amount, fee, timestamp);

	return nacl.sign.detached(data, keyPair.privateKey);
}


export function generatePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp, signature) {
	return appendBuffer(generatePaymentTransactionBase(keyPair.publicKey, lastReference, recipient, amount, fee, timestamp),
		signature);
}


export function generatePaymentTransactionRaw({seed, lastReference, recipient, amount, fee, timestamp = new Date().getTime()}) {
	let senderAccountSeed = Base58.decode(seed);
	lastReference = Base58.decode(lastReference);
	recipient = Base58.decode(recipient);
	if (senderAccountSeed.length != 32) {
		throw 'Wrong Seed'
	}

	let keyPair = core.getKeyPairFromSeed(senderAccountSeed);
	let signature = generateSignaturePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp);
	let paymentTransactionRaw = generatePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp, signature);
	return Base58.encode(paymentTransactionRaw);
}


/*
 *
 * Arbitrary Transaction V3
 *
 * */
export function generateSignatureArbitraryTransactionV3(keyPair, lastReference, service, data, fee, timestamp) {
	const base = generateArbitraryTransactionV3Base(keyPair.publicKey, lastReference, service, data, fee, timestamp);

	return nacl.sign.detached(base, keyPair.privateKey);
}


export function generateArbitraryTransactionV3(keyPair, lastReference, service, data, fee, timestamp, signature) {
	return appendBuffer(generateArbitraryTransactionV3Base(keyPair.publicKey, lastReference, service, data, fee, timestamp),
		signature);
}


export function generateArbitraryTransactionV3Raw({seed, lastReference, service, data, fee, timestamp = new Date().getTime()}) {
	let senderAccountSeed = Base58.decode(seed);
	lastReference = Base58.decode(lastReference);
	if (senderAccountSeed.length != 32) {
		throw 'Wrong Seed'
	}
	data = stringtoUTF8Array(data);
	let keyPair = core.getKeyPairFromSeed(senderAccountSeed);
	let signature = generateSignatureArbitraryTransactionV3(keyPair, lastReference, service, data, fee, timestamp);
	let raw = generateArbitraryTransactionV3(keyPair, lastReference, service, data, fee, timestamp, signature);
	return Base58.encode(raw);
}


/*
 *
 * Register Name
 *
 * */
export function generateSignatureRegisterNameTransaction(keyPair, lastReference, owner, name, value, fee, timestamp) {
	const data = generateRegisterNameTransactionBase(keyPair.publicKey, lastReference, owner, name, value, fee, timestamp);
	return nacl.sign.detached(data, keyPair.privateKey);
}


export function generateRegisterNameTransaction(keyPair, lastReference, owner, name, value, fee, timestamp, signature) {
	return appendBuffer(generateRegisterNameTransactionBase(keyPair.publicKey, lastReference, owner, name, value, fee, timestamp),
		signature);
}


export function generateRegisterNameTransactionRaw({seed, lastReference, owner, name, value, fee, timestamp = new Date().getTime()}) {
	let senderAccountSeed = Base58.decode(seed);
	lastReference = Base58.decode(lastReference);
	owner = Base58.decode(owner);
	if (senderAccountSeed.length != 32) {
		throw 'Wrong Seed'
	}
	name = stringtoUTF8Array(name);
	value = stringtoUTF8Array(value);

	let keyPair = core.getKeyPairFromSeed(senderAccountSeed);
	let signature = generateSignatureRegisterNameTransaction(keyPair, lastReference, owner, name, value, fee, timestamp);
	let raw = generateRegisterNameTransaction(keyPair, lastReference, owner, name, value, fee, timestamp, signature);
	return Base58.encode(raw);
}
