import { expect } from 'chai';
import Base58 from 'bs58';
import qoraCore from '../../src';

const qora = qoraCore.core;


describe('Qora Core', function () {
	it('genSeedByPassword()', function () {
		expect(qora.genSeedByPassword('12345678')).to.eql('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk');
	});


	it('genAccountFromSeed()', function () {
		expect(qora.genAccountFromSeed('F9ABTQMy7cwoorBqRTN6J3pLWzCDrgp3BcmQ6LdpDNAB')).to.eql({
			address: 'QSDA3jmcAoVHTfXzXCFmxauPrkaNZbdwJ2',
			publicKey: 'DU62bbT5EmBwxNagC5mD8X6S32J43oTWkXqSPTJUfCfZ',
			privateKey: '5CdztuRkfA4S6RTBVNhB3F3iqdi6WU1owbmpgTzhgLMAAX6Xe4CCFbe13qV7RXxiYfSbgAFzAkvxi1WF5hFisjcK'
		});
	});


	it('genAccounts()', function () {
		expect(qora.genAccounts('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk', 2)).to.eql([
			{
				address: 'QSDA3jmcAoVHTfXzXCFmxauPrkaNZbdwJ2',
				publicKey: 'DU62bbT5EmBwxNagC5mD8X6S32J43oTWkXqSPTJUfCfZ',
				privateKey: '5CdztuRkfA4S6RTBVNhB3F3iqdi6WU1owbmpgTzhgLMAAX6Xe4CCFbe13qV7RXxiYfSbgAFzAkvxi1WF5hFisjcK'
			},
			{
				address: 'QU5jnvZCsuw7FnZPQ7Gwgk3w7soa2ztZAS',
				publicKey: '6f6NKSk4eWQbv7zF98XcGLh6GfKtSMcNhMaBJsRgJYpQ',
				privateKey: '5ynWrUDtz6DuziLspaGXS9tbEwMXVAUgbFwKXDrV5tBfVRwsyPLWZ3VxneucQcnieyer4qaYaVoKomKXvDoxWbAg'
			}
		])
	});


	it('getKeyPairFromSeed()', function () {
		expect(qora.getKeyPairFromSeed('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk', true)).to.eql({
			publicKey: 'GoPKejW9uTgSxEeCMu4cZXntk2yYTxga4XKCiQhh2gww',
			privateKey: 'VfbAwvkVkfWMo5q5TVXE7KVYayvZjz5tUwYczP62QsBtPKZGf3dzKJLb5Rp9nsDcvQ5NcLCtd2oU3pymQiSTwho'
		});
	});


	it('generateAccountSeed()', function () {
		expect(qora.generateAccountSeed('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk', 0, true)).to.eql('F9ABTQMy7cwoorBqRTN6J3pLWzCDrgp3BcmQ6LdpDNAB');
	});


	it('getAccountAddressFromPublicKey()', function () {
		expect(qora.getAccountAddressFromPublicKey('DU62bbT5EmBwxNagC5mD8X6S32J43oTWkXqSPTJUfCfZ')).to.eql(
			'QSDA3jmcAoVHTfXzXCFmxauPrkaNZbdwJ2'
		)
	});


	it('generatePaymentTransaction()', function () {
		let signature = qora.generateSignaturePaymentTransaction({
				publicKey: Base58.decode('GoPKejW9uTgSxEeCMu4cZXntk2yYTxga4XKCiQhh2gww'),
				privateKey: Base58.decode('VfbAwvkVkfWMo5q5TVXE7KVYayvZjz5tUwYczP62QsBtPKZGf3dzKJLb5Rp9nsDcvQ5NcLCtd2oU3pymQiSTwho')
			}, Base58.decode('2Yt9Df3wfS5eS11peoGXhb254kqEvaWVnLoFq4hMbGrgsAxbx3mpqFfwuHWm15mHZ8bZtppabKV2mfoAKQxupk6Z'),
			Base58.decode('QN5XF1YQUyVt3S1LNZtStXQCbtxyhkj2FR'), 1, 1, 1456038472420);
		let transaction = qora.generatePaymentTransaction({
				publicKey: Base58.decode('GoPKejW9uTgSxEeCMu4cZXntk2yYTxga4XKCiQhh2gww'),
				privateKey: Base58.decode('VfbAwvkVkfWMo5q5TVXE7KVYayvZjz5tUwYczP62QsBtPKZGf3dzKJLb5Rp9nsDcvQ5NcLCtd2oU3pymQiSTwho')
			}, Base58.decode('2Yt9Df3wfS5eS11peoGXhb254kqEvaWVnLoFq4hMbGrgsAxbx3mpqFfwuHWm15mHZ8bZtppabKV2mfoAKQxupk6Z'),
			Base58.decode('QN5XF1YQUyVt3S1LNZtStXQCbtxyhkj2FR'), 1, 1, 1456038472420, signature);
		expect([].slice.call(transaction))
			.to.eql(Base58.decode('111C87H8UfBts3uce23bUdthTFckWSMeVez8LQSnPvmYumW6UxoaXkqfv2VK1x8iegGTW6vQrJ2Stnso5RvwHopFnHyNmfRSumVBW88T1EqxedpogqQmfZ93qoEJdXkUfNZHQ1tFJG1BKddqjVzQrju1iq6QtofvWLuvSmFZkuBe7uj8i6xwFYqkYMzLYMvi25iLzgct4pr4eTTTvogksYa5e2jgLLjfKjUTsMWtRPz6N4pzBsREN8ripfRDejQdk3q1VEDEdFuskUaTVewPNJrs61K5ubCc5'));
	});
});
