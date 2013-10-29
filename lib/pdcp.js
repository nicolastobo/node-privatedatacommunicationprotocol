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
	var enc_price = URLSafeBase64.decode(final_message)

	// (iv, p, sig) = dec_price // -- split up according to fixed lengths
	var iv = enc_price.slice(0, 3).toString('utf8');
	var p = enc_price.slice(3, 6).toString('utf8');
	var sig = enc_price.slice(6, enc_price.length).toString('utf8');

	var price_pad = _hmac(e_key, iv);
	var price = p ^ price_pad;
	var conf_sig = _hmac(i_key, price + iv);
	var success = (conf_sig == sig);

	assert(success, 'operation failed : ' + conf_sig + ' != ' + sig);

	return price;
};

var _hmac = function(k, d) {
	k = k.toString();
	d = d.toString();

	return crypto.createHmac('sha1', k).update(d).digest('hex')
};

var msg = PDCP.crypt('111', '222', '333', '444');
console.log("length of final message:", new Buffer(msg).length);
var price = PDCP.decrypt('222', '333', msg);
console.log(price);
