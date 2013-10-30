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

		var PDCP = require("privatedatacommunicationprotocol");

		var price = "15000000"; // must 8 bytes!

		// PDCP.crypt = function(iv, e_key, i_key, price)
		// iv		initialization vector (16 bytes - unique to the impression)
		// e_key	encryption key (32 bytes - provided at account set up)
		// i_key	integrity key (32 bytes - provided at account set up)
		// price	(8 bytes - in micros of account currency)
		var enc_price = PDCP.crypt('11', '222d', '33s3', price);


		// PDCP.decrypt = function(e_key, i_key, final_message)
		// e_key	encryption key, 32 bytes - provided at account set up
		// i_key	integrity key, 32 bytes - provided at account set up
		// final_message	38 characters web-safe base64 encoded
		var dec_price = PDCP.decrypt('222d', '33s3', enc_price);

		assert.equal(price, dec_price);
