<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<title>:: Sample of ASCrypt PHP library ::</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
</head>
<body>
<div style="font-size:11px;font-family:Monospace;">	
<?php

############################################################
# NOTE: File is encoded in UTF-8 so strings are UTF-8 too. #
############################################################

/**
* Include algorithms.
*/
include_once("classes/AES.php");
include_once("classes/MD5.php");
include_once("classes/SHA1.php");
include_once("classes/ARC4.php");
include_once("classes/GUID.php");
include_once("classes/Base16.php");
include_once("classes/Base64.php");
include_once("classes/SHA256.php");
include_once("classes/RMD160.php");
include_once("classes/ROT13.php");
include_once("classes/XXTEA.php");
include_once("classes/padding/PKCS7.php");
include_once("classes/padding/ZEROS.php");

/**
* Boolean to boolean string.
*/
function bool_str($bool)
{
	return $bool ? "true" : "false";
}

/**
* Input text (17 chars, 19 bytes).
*/
$input = "Hello to € World!";

/**
* Test PKCS#7 padding scheme.
*/
$pp = PKCS7::pad($input, 16);
$pup = PKCS7::unpad($pp);
//
print "PKCS#7 padded length: " . strlen($pp) . "<br/>\n";
print "PKCS#7 unpadded length: " . strlen($pup) . "<br/><br/>\n";

/**
* Test zero byte padding scheme.
*/
$zp = ZEROS::pad($input, 16);
$zup = ZEROS::unpad($zp);
//
print "Zero byte padded length: " . strlen($zp) . "<br/>\n";
print "Zero byte unpadded length: " . strlen($zup) . "<br/><br/>\n";

/**
* Test Base16 (hex) encoding.
*/
$b16enc = Base16::encode($input);
$b16dec = Base16::decode($b16enc);
//
print "Base16 encoded in UTF-8: " . $b16enc . "<br/>";
print "Base16 decoded in UTF-8: " . $b16dec . "<br/><br/>\n";

/**
* Test Base64 encoding.
*/
$b64enc = Base64::encode($input);
$b64dec = Base64::decode($b64enc);
//
print "Base64 encoded in UTF-8: " . $b64enc . "<br/>";
print "Base64 decoded in UTF-8: " . $b64dec . "<br/><br/>\n";

/**
* Test creating GUID's.
*/
print "Created GUID 1: " . GUID::create() . "<br/>";
print "Created GUID 2: " . GUID::create() . "<br/>";
print "Created GUID 3: " . GUID::create() . "<br/><br/>\n";

/**
* Test ROT13 encoding.
*/
$rot13enc = ROT13::encode($input);
$rot13dec = ROT13::decode($rot13enc);
//
print "ROT13 encoded in UTF-8: " . $rot13enc . "<br/>\n";
print "ROT13 decoded in UTF-8: " . $rot13dec . "<br/><br/>\n";

/**
* Test MD5 with one official test vector and custom input.
* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
*/
$md5 = MD5::compute($input);
$md5tv = MD5::compute("");
$md5hmac = MD5::computeHMAC("1234567890123456", $input);
//
print "MD5 from otv is ok: " . bool_str(Base16::encode($md5tv) == "d41d8cd98f00b204e9800998ecf8427e") . "<br/>\n";
print "MD5 HMAC in UTF-8: " . Base16::encode($md5hmac) . "<br/>\n";
print "MD5 in UTF-8: " . Base16::encode($md5) . "<br/><br/>\n";

/**
* Test RIPEMD-160 with one official test vector and custom input.
* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
*/
$rmd160 = RMD160::compute($input);
$rmd160tv = RMD160::compute("");
$rmd160hmac = RMD160::computeHMAC("1234567890123456", $input);
//
print "RIPEMD-160 from otv is ok: " . bool_str(Base16::encode($rmd160tv) == "9c1185a5c5e9fc54612808977ee8f548b2258d31") . "<br/>\n";
print "RIPEMD-160 HMAC in UTF-8: " . Base16::encode($rmd160hmac) . "<br/>\n";
print "RIPEMD-160 in UTF-8: " . Base16::encode($rmd160) . "<br/><br/>\n";

/**
* Test SHA-1 with one official test vector and custom input.
* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
*/
$sha1 = SHA1::compute($input);
$sha1tv = SHA1::compute("");
$sha1hmac = SHA1::computeHMAC("1234567890123456", $input);
//
print "SHA-1 from otv is ok: " . bool_str(Base16::encode($sha1tv) == "da39a3ee5e6b4b0d3255bfef95601890afd80709") . "<br/>\n";
print "SHA-1 HMAC in UTF-8: " . Base16::encode($sha1hmac) . "<br/>\n";
print "SHA-1 in UTF-8: " . Base16::encode($sha1) . "<br/><br/>\n";

/**
* Test SHA-256 with one official test vector and custom input.
* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
*/
$sha256 = SHA256::compute($input);
$sha256tv = SHA256::compute("");
$sha256hmac = SHA256::computeHMAC("1234567890123456", $input);
//
print "SHA-256 from otv is ok: " . bool_str(Base16::encode($sha256tv) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") . "<br/>\n";
print "SHA-256 HMAC in UTF-8: " . Base16::encode($sha256hmac) . "<br/>\n";
print "SHA-256 in UTF-8: " . Base16::encode($sha256) . "<br/><br/>\n";

/**
* Test ARC4 with one official test vector and custom input.
* Vectors from: http://reikon.us/arc4
*/
$arc4tvk = Base16::decode("0123456789abcdef");
$arc4tvt = Base16::decode("0123456789abcdef");
$arc4tve = ARC4::encrypt($arc4tvk, $arc4tvt);
$arc4tvd = ARC4::decrypt($arc4tvk, $arc4tve);
//
$arc4k = "1234567890123456";
$arc4e = ARC4::encrypt($arc4k, $input);
$arc4d = ARC4::decrypt($arc4k, $arc4e);
//
print "ARC4 otv encrypted is ok: " . bool_str(Base16::encode($arc4tve) == "75b7878099e0c596") . "<br/>\n";
print "ARC4 otv decrypted is ok: " . bool_str(Base16::encode($arc4tvd) == "0123456789abcdef") . "<br/>\n";
print "ARC4 encrypted in UTF-8: " . Base16::encode($arc4e) . "<br/>\n";
print "ARC4 decrypted in UTF-8: " . $arc4d . "<br/><br/>\n";

/**
* Test XXTEA with one official test vector and custom input.
* Vectors from: http://www.crypt.co.za/post/27
*/
$xxttvk = Base16::decode("9e3779b99b9773e9b979379e6b695156");
$xxttvt = Base16::decode("0102040810204080fffefcf8f0e0c080");
$xxttve = XXTEA::encrypt($xxttvk, $xxttvt);
$xxttvd = XXTEA::decrypt($xxttvk, $xxttve);
//
$xxteak = "1234567890123456";
$xxteae = XXTEA::encrypt($xxteak, PKCS7::pad($input, 4)); // Needs padding.
$xxtead = PKCS7::unpad(XXTEA::decrypt($xxteak, $xxteae)); // Needs unpadding.
//
print "XXTEA otv encrypted is ok: " . bool_str(Base16::encode($xxttve) == "01b815fd2e4894d13555da434c9d868a") . "<br/>\n";
print "XXTEA otv decrypted is ok: " . bool_str(Base16::encode($xxttvd) == "0102040810204080fffefcf8f0e0c080") . "<br/>\n";
print "XXTEA encrypted in UTF-8: " . Base16::encode($xxteae) . "<br/>\n";
print "XXTEA decrypted in UTF-8: " . $xxtead . "<br/><br/>\n";

/**
* Test AES-128 with one official test vector and custom input.
* Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/
$aes128tvk = pack("c*", 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f);
$aes128tvt = pack("c*", 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
$aes128tve = AES::encrypt($aes128tvk, $aes128tvt); // ECB mode, no padding needed.
$aes128tvd = AES::decrypt($aes128tvk, $aes128tve); // ECB mode, no padding needed.
//
$aes128k = "1234567890123456";
$aes128e = AES::encrypt($aes128k, PKCS7::pad($input, 16)); // Needs padding.
$aes128d = PKCS7::unpad(AES::decrypt($aes128k, $aes128e)); // Needs unpadding.
//
print "AES-128 otv encrypted is ok: " . bool_str(Base16::encode($aes128tve) == "69c4e0d86a7b0430d8cdb78070b4c55a") . "<br/>\n";
print "AES-128 otv decrypted is ok: " . bool_str(Base16::encode($aes128tvd) == "00112233445566778899aabbccddeeff") . "<br/>\n";
print "AES-128 (ECB mode) encrypted in UTF-8: " . Base16::encode($aes128e) . "<br/>\n";
print "AES-128 (ECB mode) decrypted in UTF-8: " . $aes128d . "<br/><br/>\n";

/**
* Test AES-192 with one official test vector and custom input.
* Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/
$aes192tvk = pack("c*", 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17);
$aes192tvt = pack("c*", 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
$aes192tve = AES::encrypt($aes192tvk, $aes192tvt); // ECB mode, no padding needed.
$aes192tvd = AES::decrypt($aes192tvk, $aes192tve); // ECB mode, no padding needed.
//
$aes192i = "1234567890123456";
$aes192k = "123456789012345678901234";
$aes192e = AES::encrypt($aes192k, PKCS7::pad($input, 16), "cbc", $aes192i); // Needs padding.
$aes192d = PKCS7::unpad(AES::decrypt($aes192k, $aes192e, "cbc", $aes192i)); // Needs unpadding.
//
print "AES-192 otv encrypted is ok: " . bool_str(Base16::encode($aes192tve) == "dda97ca4864cdfe06eaf70a0ec0d7191") . "<br/>\n";
print "AES-192 otv decrypted is ok: " . bool_str(Base16::encode($aes192tvd) == "00112233445566778899aabbccddeeff") . "<br/>\n";
print "AES-192 (CBC mode) encrypted in UTF-8: " . Base16::encode($aes192e) . "<br/>\n";
print "AES-192 (CBC mode) decrypted in UTF-8: " . $aes192d . "<br/><br/>\n";

/**
* Test AES-256 with one official test vector and custom input.
* Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/
$aes256tvk = pack("c*", 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f);
$aes256tvt = pack("c*", 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
$aes256tve = AES::encrypt($aes256tvk, $aes256tvt); // ECB mode, no padding needed.
$aes256tvd = AES::decrypt($aes256tvk, $aes256tve); // ECB mode, no padding needed.
//
$aes256i = "1234567890123456";
$aes256k = "12345678901234561234567890123456";
$aes256e = AES::encrypt($aes256k, PKCS7::pad($input, 16), "ctr", $aes256i); // Needs padding.
$aes256d = PKCS7::unpad(AES::decrypt($aes256k, $aes256e, "ctr", $aes256i)); // Needs unpadding.
//
print "AES-256 otv encrypted is ok: " . bool_str(Base16::encode($aes256tve) == "8ea2b7ca516745bfeafc49904b496089") . "<br/>\n";
print "AES-256 otv decrypted is ok: " . bool_str(Base16::encode($aes256tvd) == "00112233445566778899aabbccddeeff") . "<br/>\n";
print "AES-256 (CTR mode) encrypted in UTF-8: " . Base16::encode($aes256e) . "<br/>\n";
print "AES-256 (CTR mode) decrypted in UTF-8: " . $aes256d . "<br/><br/>\n";

?>

</div>
</body>
</html>
