/*jslint node: true*/
/*global describe:false, it:false */
"use strict";

var assert = require("assert");
var PDCP   = require("../lib/pdcp");

var e_key = new Buffer([
  0xb0, 0x8c, 0x70, 0xcf, 0xbc, 0xb0, 0xeb, 0x6c,
  0xab, 0x7e, 0x82, 0xc6, 0xb7, 0x5d, 0xa5, 0x20,
  0x72, 0xae, 0x62, 0xb2, 0xbf, 0x4b, 0x99, 0x0b,
  0xb8, 0x0a, 0x48, 0xd8, 0x14, 0x1e, 0xec, 0x07
]);

var i_key = new Buffer([
  0xbf, 0x77, 0xec, 0x55, 0xc3, 0x01, 0x30, 0xc1,
  0xd8, 0xcd, 0x18, 0x62, 0xed, 0x2a, 0x4c, 0xd2,
  0xc7, 0x6a, 0xc3, 0x3b, 0xc0, 0xc4, 0xce, 0x8a,
  0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92
]);


describe('PDCP', function() {

  it('shoud decrypt the google code example', function(done) {
    var enc_price = 'SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA';
    var dec_price = PDCP.decrypt(e_key, i_key, enc_price);
    assert.equal(709959680, dec_price);
    done();
  });

  it('shoud crypt the google code example with different result', function(done) {
    var price = 709959680;
    var enc_price = PDCP.crypt(e_key, i_key, price);
    assert.notEqual('SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA', enc_price);
    var dec_price = PDCP.decrypt(e_key, i_key, enc_price);
    assert.equal(709959680, dec_price);
    done();
  });


  it('shoud crypt/decrypt properly', function(done) {
    var price = 158624569;
    var enc_price = PDCP.crypt(e_key, i_key, price);
    var dec_price = PDCP.decrypt(e_key, i_key, enc_price);

    assert.equal(price, dec_price);

    done();
  });

  it('crypt same price twice provide different result', function(done) {
    var price   = 10000000;
    var enc_price1 = PDCP.crypt(e_key, i_key, price);
    var enc_price2 = PDCP.crypt(e_key, i_key, price);
    assert.notEqual(enc_price1, enc_price2);
    done();
  });

  it('crypt same price twice with same iv provide same result', function(done) {
    var price   = 10000000;
    var iv = new Buffer([0x00, 0x8c, 0x70, 0xcf, 0xbc, 0xb0, 0xeb, 0x6c, 0xab, 0x7e, 0x82, 0xc6, 0xb7, 0x5d, 0xa5, 0x21]);
    var enc_price1 = PDCP.crypt(e_key, i_key, price, iv);
    var enc_price2 = PDCP.crypt(e_key, i_key, price, iv);
    assert.equal(enc_price1, enc_price2);
    done();
  });



  it('crypt/decrypt 1000 random number', function(done) {
    var price;
    for(var i=0; i< 1000; i++){
      price = Math.floor(Math.random()*1000000000);
      var enc_price = PDCP.crypt(e_key, i_key, price);
      var dec_price = PDCP.decrypt(e_key, i_key, enc_price);
      assert.equal(price, dec_price);
    }
    done();
  });

});
