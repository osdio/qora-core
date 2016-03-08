import { expect } from 'chai';
import * as core from '../../src/core';


describe('core', function () {
	it('encrypt', function () {
		expect(core.encrypt('12345678', '12345678')).to.eql('MbpDrSiL2rjaVqwPcGu3UDvXBhKcj9w9S');
	});


	it('decrypt', function () {
		expect(core.decrypt('MbpDrSiL2rjaVqwPcGu3UDvXBhKcj9w9S', '12345678')).to.eql('12345678');
	});


	it('generateSeedByPassword()', function () {
		expect(core.generateSeedByPassword('12345678')).to.eql('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk');
	});


	it('generateAccountFromSeed()', function () {
		expect(core.generateAccountFromSeed('F9ABTQMy7cwoorBqRTN6J3pLWzCDrgp3BcmQ6LdpDNAB')).to.eql({
			address: 'QSDA3jmcAoVHTfXzXCFmxauPrkaNZbdwJ2',
			publicKey: 'DU62bbT5EmBwxNagC5mD8X6S32J43oTWkXqSPTJUfCfZ',
			privateKey: '5CdztuRkfA4S6RTBVNhB3F3iqdi6WU1owbmpgTzhgLMAAX6Xe4CCFbe13qV7RXxiYfSbgAFzAkvxi1WF5hFisjcK'
		});
	});


	it('generateAccounts()', function () {
		expect(core.generateAccounts('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk', 2)).to.eql([
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
		expect(core.getKeyPairFromSeed('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk', true)).to.eql({
			publicKey: 'GoPKejW9uTgSxEeCMu4cZXntk2yYTxga4XKCiQhh2gww',
			privateKey: 'VfbAwvkVkfWMo5q5TVXE7KVYayvZjz5tUwYczP62QsBtPKZGf3dzKJLb5Rp9nsDcvQ5NcLCtd2oU3pymQiSTwho'
		});
	});


	it('generateAccountSeed()', function () {
		expect(core.generateAccountSeed('2fVmtpyoK6FHYRxmWvnA61sAUZPHmNoau38uFtBQxwTk', 0, true)).to.eql('F9ABTQMy7cwoorBqRTN6J3pLWzCDrgp3BcmQ6LdpDNAB');
	});


	it('getAccountAddressFromPublicKey()', function () {
		expect(core.getAccountAddressFromPublicKey('DU62bbT5EmBwxNagC5mD8X6S32J43oTWkXqSPTJUfCfZ')).to.eql(
			'QSDA3jmcAoVHTfXzXCFmxauPrkaNZbdwJ2'
		)
	});
});
