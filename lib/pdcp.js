var crypto 			= require("crypto");
var assert 			= require("assert");
var URLSafeBase64 	= require('urlsafe-base64');

// privatedatacommunicationprotocol from Google
// developed for decrypt price in Google RTB protocol (https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price)
var PDCP = function () {
};

// iv		initialization vector (16 bytes - unique to the impression)
// e_key	encryption key (32 bytes - provided at account set up)
// i_key	integrity key (32 bytes - provided at account set up)
// price	(8 bytes - in micros of account currency)
PDCP.crypt = function(iv, e_key, i_key, price) {
	assert(iv.length == 2, 'iv must have 32 bytes');
	assert(e_key.length == 4, 'e_key must have 32 bytes');
	assert(i_key.length == 4, 'i_key must have 32 bytes');
	assert(price.length == 8, 'price must have 8 char');

	var pad = _hmac(e_key, iv);  // first 8 bytes
	var enc_price = pad ^ price;
	var signature = _hmac(i_key, price + iv);  // first 4 bytes

	var final_message = URLSafeBase64.encode(new Buffer(iv + enc_price + signature));

	return final_message;
};

// e_key	encryption key, 32 bytes - provided at account set up
// i_key	integrity key, 32 bytes - provided at account set up
// final_message	38 characters web-safe base64 encoded
PDCP.decrypt = function(e_key, i_key, final_message) {
	assert(e_key.length == 4, 'e_key must have 32 bytes');
	assert(i_key.length == 4, 'i_key must have 32 bytes');

	var enc_price = URLSafeBase64.decode(final_message)

	// (iv, p, sig) = dec_price // -- split up according to fixed lengths
	var iv = enc_price.slice(0, 2).toString('utf8'); // 2 bytes
	var p = enc_price.slice(2, 10).toString('utf8'); // 8 bytes
	var sig = enc_price.slice(10, enc_price.length).toString('utf8');

	var price_pad = _hmac(e_key, iv);
	var price = p ^ price_pad;
	var conf_sig = _hmac(i_key, price + iv);
	var success = (conf_sig == sig);

	if (!success)
		throw new Error("decrypt: signatures are different. Can't decrypt!");

	return price;
};

var _hmac = function(k, d) {
	k = k.toString();
	d = d.toString();

	return crypto.createHmac('sha1', k).update(d).digest('hex')
};

module.exports = PDCP;
