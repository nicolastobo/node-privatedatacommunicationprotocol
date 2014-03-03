/*jslint node: true */
"use strict";

var crypto        = require("crypto");
var URLSafeBase64 = require('urlsafe-base64');

function hmac (k, d) {
  return crypto.createHmac('sha1', k).update(d).digest();
}

function xor (a, b) {
  var res = [], i = Math.min(a.length, b.length);
  while (i--)
    res.unshift(a[i] ^ b[i]);
  return new Buffer(res);
}

var PDCP = function () {};

/**
 * @param  {Buffer} e_key encryption key (32 bytes - provided at account set up)
 * @param  {Buffer} i_key integrity key (32 bytes - provided at account set up)
 * @param  {number} price in micros of account currency
 * @param  {Buffer} iv    [OPTION] initialization vector (16 bytes - unique to the impression)
 * @return {string}       URLSafeBase64
 */
PDCP.crypt = function (e_key, i_key, price, iv) {

  if(! Buffer.isBuffer(e_key)) throw('Invalid e_key is not a Buffer');
  if(e_key.length != 32)       throw('Invalid e_key is not 32 bytes');
  if(! Buffer.isBuffer(i_key)) throw('Invalid i_key is not a Buffer');
  if(i_key.length != 32)       throw('Invalid i_key is not 32 bytes');

  if (iv) {
    if(! Buffer.isBuffer(iv))  throw('Invalid iv is not a Buffer');
    if(iv.length != 16)        throw('Invalid iv is not 16 bytes');
  } else {
    iv = new Buffer(16);
    iv.writeUInt16BE(Math.round(Math.random() * 65535), 0);
  }

  var bprice = new Buffer(8);
  bprice.writeUInt32BE(price,4);

  var pad     = hmac(e_key, iv),
    enc_price = xor(pad, bprice),
    conf_sig  = hmac(i_key, Buffer.concat([bprice, iv])),
    result    = Buffer.concat([iv, enc_price, conf_sig]).slice(0,28);

  return URLSafeBase64.encode(result);
};

/**
 * @param  {Buffer} e_key        encryption key (32 bytes - provided at account set up)
 * @param  {Buffer} i_key        integrity key (32 bytes - provided at account set up)
 * @param  {string} encodedPrice URLSafeBase64
 * @return {number}
 */
PDCP.decrypt = function (e_key, i_key, encodedPrice) {

  if(! Buffer.isBuffer(e_key))                throw('Invalid e_key is not a Buffer');
  if(e_key.length != 32)                      throw('Invalid e_key is not 32 bytes');
  if(! Buffer.isBuffer(i_key))                throw('Invalid i_key is not a Buffer');
  if(i_key.length != 32)                      throw('Invalid i_key is not 32 bytes');

  if (! URLSafeBase64.validate(encodedPrice)) throw('encodedPrice is not a URLSafeBase64');
  if (encodedPrice.length != 38)              throw('encodedPrice must have 38 char. length');

  var enc_price = URLSafeBase64.decode(encodedPrice),
    iv          = enc_price.slice(0, 16),
    p           = enc_price.slice(16, 24),
    sig         = enc_price.slice(24, 28),
    pad         = hmac(e_key, iv),
    price       = xor(p, pad),
    conf_sig    = hmac(i_key, Buffer.concat([price, iv])).slice(0,4);

  if (conf_sig.toString() === sig.toString()) {
    return price.readUInt32BE(4);
  } else {
    return null;
  }
};

module.exports = PDCP;
