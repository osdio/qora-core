import { expect } from 'chai';
import Base58 from 'bs58';

import * as transaction from '../../src/transaction';
import  mock from '../mock';


describe('transaction', function () {
	it('payment', function () {
		expect(transaction.generatePaymentTransactionRaw(mock.payment)).to.eql(mock.payment.tx);
	});


	it('generateSignatureArbitraryTransactionV3', function () {
		expect(transaction.generateArbitraryTransactionV3Raw(mock.arbitraryTransactionV3)).to.eql(mock.arbitraryTransactionV3.tx);
	});


	it('generateRegisterNameTransactionRaw', function () {
		expect(transaction.generateRegisterNameTransactionRaw(mock.name)).to.eql(mock.name.tx);
	})
});
