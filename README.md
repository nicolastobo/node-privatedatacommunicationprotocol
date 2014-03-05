node-privatedatacommunicationprotocol
=====================================

Implementation in NodeJs of privatedatacommunicationprotocol from Google
https://code.google.com/p/privatedatacommunicationprotocol/

needed for https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price

Installation
============

		npm install privatedatacommunicationprotocol
		
Example
=======

		var assert = require("assert");
		var PDCP = require("privatedatacommunicationprotocol");

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

		var iv = new Buffer([
		  0xd8, 0xcd, 0x18, 0x62, 0xed, 0x2a, 0x4c, 0xd2,
		  0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92
		]);

		var price = 15000000;

		// PDCP.crypt = function(e_key, i_key, price, iv)
		// iv		initialization vector (16 bytes - unique to the impression)
		// e_key	encryption key (32 bytes - provided at account set up)
		// i_key	integrity key (32 bytes - provided at account set up)
		// price	(8 bytes - in micros of account currency)
		var enc_price = PDCP.crypt(e_key, i_key, price, iv);


		// PDCP.decrypt = function(e_key, i_key, final_message)
		// e_key	encryption key, 32 bytes - provided at account set up
		// i_key	integrity key, 32 bytes - provided at account set up
		// final_message	38 characters web-safe base64 encoded
		var dec_price = PDCP.decrypt(e_key, i_key, enc_price);

		assert.equal(price, dec_price);
