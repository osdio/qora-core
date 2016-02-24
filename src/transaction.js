import Base58 from 'bs58';
import {
	doubleSha256,
	wordToBytes,
	appendBuffer,
	int32ToBytes,
	generateArbitraryTransactionV3Base,
	generateRegisterNameTransactionBase,
	generatePaymentTransactionBase
} from './utils';
import * as core from './core';


/*
 *
 * Simple Payment
 *
 * */
export function generateSignaturePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp) {
	const data = generatePaymentTransactionBase(keyPair.publicKey, lastReference, recipient, amount, fee, timestamp);
	return nacl.crypto_sign_detached(data, keyPair.privateKey);
}


export function generatePaymentTransaction(keyPair, lastReference, recipient, amount, fee, timestamp, signature) {
	return appendBuffer(generatePaymentTransactionBase(keyPair.publicKey, lastReference, recipient, amount, fee, timestamp),
		signature);
}


export function generatePaymentTransactionRaw(seed, lastReference, recipientAccountAddress, amount, fee, timestamp = new Date().getTime()) {
	let senderAccountSeed = Base58.decode(seed);
	if (senderAccountSeed.length != 32) {
		throw 'Wrong Seed'
	}

	let keyPair = core.getKeyPairFromSeed(senderAccountSeed);
	let signature = generateSignaturePaymentTransaction(keyPair, lastReference, recipientAccountAddress, amount, fee, timestamp);
	let paymentTransactionRaw = generatePaymentTransaction(keyPair, lastReference, recipientAccountAddress, amount, fee, timestamp, signature);
	return Base58.encode(paymentTransactionRaw);
}


/*
 *
 * Arbitrary Transaction V3
 *
 * */
export function generateSignatureArbitraryTransactionV3(keyPair, lastReference, service, arbitraryData, fee, timestamp) {
	const data = generateArbitraryTransactionV3Base(keyPair.publicKey, lastReference, service, arbitraryData, fee, timestamp);
	return nacl.sign.detached(data, keyPair.privateKey);
}


export function generateArbitraryTransactionV3(keyPair, lastReference, service, arbitraryData, fee, timestamp, signature) {
	return appendBuffer(generateArbitraryTransactionV3Base(keyPair.publicKey, lastReference, service, arbitraryData, fee, timestamp),
		signature);
}


export function getArbitraryTransactionV3Raw(base58SenderAccountSeed, base58LastReferenceOfAccount, service, arbitraryData, fee, timestamp = new Date().getTime()) {
	let senderAccountSeed = Base58.decode(base58SenderAccountSeed);
	if (senderAccountSeed.length != 32) {
		throw 'Wrong Seed'
	}

	let keyPair = core.getKeyPairFromSeed(senderAccountSeed);
	let signature = generateSignatureArbitraryTransactionV3(keyPair, base58LastReferenceOfAccount, service, arbitraryData, fee, timestamp);
	let raw = generateArbitraryTransactionV3(keyPair, base58LastReferenceOfAccount, service, arbitraryData, fee, timestamp, signature);
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


export function generateRegisterNameTransactionRaw(base58SenderAccountSeed, base58LastReferenceOfAccount, owner, name, value, fee, timestamp = new Date().getTime()) {
	let senderAccountSeed = Base58.decode(base58SenderAccountSeed);
	if (senderAccountSeed.length != 32) {
		throw 'Wrong Seed'
	}

	let keyPair = core.getKeyPairFromSeed(senderAccountSeed);
	let signature = generateSignatureRegisterNameTransaction(keyPair, base58LastReferenceOfAccount, owner, name, value, fee, timestamp);
	let raw = generateRegisterNameTransaction(keyPair, base58LastReferenceOfAccount, owner, name, value, fee, timestamp, signature);
	return Base58.encode(raw);
}
