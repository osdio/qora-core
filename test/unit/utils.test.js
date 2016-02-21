import { expect } from 'chai';
import * as utils from '../../src/utils';


describe('utils.js', function () {
	it('doubleSha256()', function () {
		expect(utils.doubleSha256("12345678")).to.eql(
			new Int8Array([24, -72, 74, -27, -78, 78, 101, 24, 66, -43, 43, -113, -56, -23, -2, -16, 75, -85, -98, 49, 105, -82, 122, 61, 68, 75, -25, -26, -111, -7, -94, -81])
		);
	});


	it('wordToBytes()', function () {
		expect(utils.wordToBytes(1)).to.eql([0, 0, 0, 1]);
	});


	it('int64ToBytes()', function () {
		expect(utils.int64ToBytes(1)).to.eql([0, 0, 0, 0, 0, 0, 0, 1]);
	})
});
