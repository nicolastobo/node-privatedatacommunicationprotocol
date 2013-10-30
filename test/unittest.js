"use strict";

var assert 				= require("assert");
var PDCP 				= require("../lib/pdcp");

describe('PDCP test', function() {

	before(function(done) {
		done();
	});

	it('shoud report totals properly', function(done) {
		var price = '15000000';
		var enc_price = PDCP.crypt('11', '222d', '33s3', price);
		var dec_price = PDCP.decrypt('222d', '33s3', enc_price);

		assert.equal(price, dec_price);

		done();
	});

	it('shoud report totals properly', function(done) {
		var price = '45612345';
		var enc_price = PDCP.crypt('11', '2222', 'e333', price);
		var dec_price = PDCP.decrypt('2222', 'e333', enc_price);

		assert.equal(price, dec_price);

		done();
	});
});
