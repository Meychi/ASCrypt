/***************************************************************
* NOTE: This file is in UTF-8 encoding so are the strings too! *
****************************************************************/

import org.ascrypt.*;
import org.ascrypt.common.*;
import org.ascrypt.padding.*;
import org.ascrypt.encoding.*;
import org.ascrypt.utilities.*;

class Main 
{
	/**
	* Entry point of the application.
	*/
	public static function main():Void
	{
		var main:Main = new Main();
		main.prepareConsole();
		main.testAlgorithms();
	}
	
	/**
	* Adds the console to the root.
	*/
	private function prepareConsole():Void
	{
		var console:TextField = _root.createTextField("console", 1, 5, 5, 890, 590);
		console.multiline = true;
		var format:TextFormat = new TextFormat();
		format.bold = true;
		format.color = 0x333333; 
		format.font = "Consolas";
		console.setNewTextFormat(format);
	}
	
	/**
	* The output variable for results.
	*/
	private var output:String = "";
	
	/**
	* Write line to the output.
	*/
	private function writeLine(msg:String):Void
	{
		this.output += msg + "\n";
	}

	/**
	* Test all ASCrypt main classes.
	*/
	private function testAlgorithms():Void
	{
		try 
		{
			var start:Number = getTimer();
			
			/**
			* Input length is 17 chars but 19 bytes.
			*/
			var input:String = "Hello to € World!";
			
			/**
			* Arrays for padding testing.
			*/
			var pb:Array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
			var nb:Array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
			
			/**
			* Test PKCS#7 padding.
			*/
			var pp:Array = PKCS7.pad(pb, 8);
			var pu:Array = PKCS7.unpad(pp);
			//
			writeLine("PKCS#7 padded: " + pp);
			writeLine("PKCS#7 unpadded: " + pu);
			writeLine("");
			
			/**
			* Test zero byte padding.
			*/
			var np:Array = ZEROS.pad(nb, 8);
			var nu:Array = ZEROS.unpad(np);
			//
			writeLine("Zero byte padded: " + np);
			writeLine("Zero byte unpadded: " + nu);
			writeLine("");
			
			/**
			* Text to bytes conversion from input.
			*/
			var utf8Bytes:Array = UTF8.textToBytes(input);
			var uleBytes:Array = LittleEndian.textToBytes(input);
			var ubeBytes:Array = BigEndian.textToBytes(input);
			//
			writeLine("UTF-16 BE bytes: " + ubeBytes);
			writeLine("UTF-16 LE bytes: " + uleBytes);
			writeLine("UTF-8 bytes: " + utf8Bytes);
			writeLine("");
			
			/**
			* Test base16 (hex) encoding.
			*/
			var b16utf8enc:String = Base16.encode(utf8Bytes);
			var b16utf8dec:Array = Base16.decode(b16utf8enc);
			//
			writeLine("Base16 encoded in UTF-8: " + b16utf8enc);
			writeLine("Base16 decoded in UTF-8: " + b16utf8dec);
			writeLine("");
			
			/**
			* Test base64 encoding.
			*/
			var b64utf8enc:String = Base64.encode(utf8Bytes);
			var b64utf8dec:Array = Base64.decode(b64utf8enc);
			//
			writeLine("Base64 encoded in UTF-8: " + b64utf8enc);
			writeLine("Base64 decoded in UTF-8: " + b64utf8dec);
			writeLine("");
			
			/**
			* Test creating GUID's.
			*/
			var guid1:String = GUID.create();
			var guid2:String = GUID.create();
			var guid3:String = GUID.create();
			//
			writeLine("Generated GUID 1: " + guid1);
			writeLine("Generated GUID 2: " + guid2);
			writeLine("Generated GUID 3: " + guid3);
			writeLine("");
			
			/**
			* Test ROT13 encoding.
			*/
			var r13enc:Array = ROT13.encode(utf8Bytes);
			var r13dec:Array = ROT13.decode(r13enc);
			//
			writeLine("ROT13 encoded in UTF-8: " + UTF8.bytesToText(r13enc));
			writeLine("ROT13 decoded in UTF-8: " + UTF8.bytesToText(r13dec));
			writeLine("");
			
			/**
			* Test MD5 with one official test vector and custom input.
			* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
			*/
			var md5tv:Array = MD5.compute([]);
			var md5utf8:Array = MD5.compute(utf8Bytes);
			var md5key:Array = UTF8.textToBytes("1234567890123456");
			var md5hmac:Array = MD5.computeHMAC(md5key, utf8Bytes);
			//
			writeLine("MD5 from otv is ok: " + (Base16.encode(md5tv) == "d41d8cd98f00b204e9800998ecf8427e"));
			writeLine("MD5 HMAC in UTF-8: " + Base16.encode(md5hmac));
			writeLine("MD5 in UTF-8: " + Base16.encode(md5utf8));
			writeLine("");
			
			/**
			* Test RIPEMD-160 with one official test vector and custom input.
			* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
			*/
			var rmd160tv:Array = RMD160.compute([]);
			var rmd160utf8:Array = RMD160.compute(utf8Bytes);
			var rmd160key:Array = UTF8.textToBytes("1234567890123456");
			var rmd160hmac:Array = RMD160.computeHMAC(rmd160key, utf8Bytes);
			//
			writeLine("RMD-160 from otv is ok: " + (Base16.encode(rmd160tv) == "9c1185a5c5e9fc54612808977ee8f548b2258d31"));
			writeLine("RMD-160 HMAC in UTF-8: " + Base16.encode(rmd160hmac));
			writeLine("RMD-160 in UTF-8: " + Base16.encode(rmd160utf8));
			writeLine("");
			
			/**
			* Test SHA-1 with one official test vector and custom input.
			* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
			*/
			var sha1tv:Array = SHA1.compute([]);
			var sha1utf8:Array = SHA1.compute(utf8Bytes);
			var sha1key:Array = UTF8.textToBytes("1234567890123456");
			var sha1hmac:Array = SHA1.computeHMAC(sha1key, utf8Bytes);
			//
			writeLine("SHA-1 from otv is ok: " + (Base16.encode(sha1tv) == "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
			writeLine("SHA-1 HMAC in UTF-8: " + Base16.encode(sha1hmac));
			writeLine("SHA-1 in UTF-8: " + Base16.encode(sha1utf8));
			writeLine("");
			
			/**
			* Test SHA-256 with one official test vector and custom input.
			* Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
			*/
			var sha256tv:Array = SHA256.compute([]);
			var sha256utf8:Array = SHA256.compute(utf8Bytes);
			var sha256key:Array = UTF8.textToBytes("1234567890123456");
			var sha256hmac:Array = SHA256.computeHMAC(sha256key, utf8Bytes);
			//
			writeLine("SHA-256 from otv is ok: " + (Base16.encode(sha256tv) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
			writeLine("SHA-256 HMAC in UTF-8: " + Base16.encode(sha256hmac));
			writeLine("SHA-256 in UTF-8: " + Base16.encode(sha256utf8));
			writeLine("");
			
			/**
			* Test ARC4 with one official test vector and custom input.
			* Vectors from: http://reikon.us/arc4
			*/
			var arc4tvk:Array = Base16.decode("0123456789abcdef");
			var arc4tvt:Array = Base16.decode("0123456789abcdef");
			var arc4tve:Array = ARC4.encrypt(arc4tvk, arc4tvt, true);
			var arc4tvd:Array = ARC4.decrypt(arc4tvk, arc4tve, true);
			//
			var arc4key:Array = UTF8.textToBytes("1234567890123456");
			var arc4enc:Array = ARC4.encrypt(arc4key, utf8Bytes, true);
			var arc4dec:Array = ARC4.decrypt(arc4key, arc4enc, true);
			//
			writeLine("ARC4 otv encrypted is ok: " + (Base16.encode(arc4tve) == "75b7878099e0c596"));
			writeLine("ARC4 otv decrypted is ok: " + (Base16.encode(arc4tvd) == "0123456789abcdef"));
			writeLine("ARC4 encrypted in UTF-8: " + Base16.encode(arc4enc));
			writeLine("ARC4 decrypted in UTF-8: " + UTF8.bytesToText(arc4dec));
			writeLine("");
			
			/**
			* Test XXTEA with one official test vector and custom input.
			* Vectors from: http://www.crypt.co.za/post/27
			*/
			var xxttvk:Array = Base16.decode("9e3779b99b9773e9b979379e6b695156");
			var xxttvt:Array = Base16.decode("0102040810204080fffefcf8f0e0c080");
			var xxttve:Array = XXTEA.encrypt(xxttvk, xxttvt);
			var xxttvd:Array = XXTEA.decrypt(xxttvk, xxttve);
			//
			var xxtkey:Array = UTF8.textToBytes("1234567890123456");
			var xxtenc:Array = XXTEA.encrypt(xxtkey, PKCS7.pad(utf8Bytes, 4)); // Needs padding.
			var xxtdec:Array = PKCS7.unpad(XXTEA.decrypt(xxtkey, xxtenc)); // Needs unpadding.
			//
			writeLine("XXTEA otv encrypted is ok: " + (Base16.encode(xxttve) == "01b815fd2e4894d13555da434c9d868a"));
			writeLine("XXTEA otv decrypted is ok: " + (Base16.encode(xxttvd) == "0102040810204080fffefcf8f0e0c080"));
			writeLine("XXTEA encrypted in UTF-8: " + Base16.encode(xxtenc));
			writeLine("XXTEA decrypted in UTF-8: " + UTF8.bytesToText(xxtdec));
			writeLine("");
			
			/**
			* Test AES-128 with one official test vector and custom input.
			* Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
			*/
			var aes128tvk:Array = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
			var aes128tvt:Array = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
			var aes128tve:Array = AES.encrypt(aes128tvk, aes128tvt); // No padding needed.
			var aes128tvd:Array = AES.decrypt(aes128tvk, aes128tve); // No padding needed.
			//
			var aes128key:Array = UTF8.textToBytes("1234567890123456");
			var aes128enc:Array = AES.encrypt(aes128key, PKCS7.pad(utf8Bytes, 16)); // Encrypt in ECB. Needs padding.
			var aes128dec:Array = PKCS7.unpad(AES.decrypt(aes128key, aes128enc)); // Decrypt in ECB. Needs unpadding.
			//
			writeLine("AES-128 otv encrypted is ok: " + (Base16.encode(aes128tve) == "69c4e0d86a7b0430d8cdb78070b4c55a"));
			writeLine("AES-128 otv decrypted is ok: " + (Base16.encode(aes128tvd) == "00112233445566778899aabbccddeeff"));
			writeLine("AES-128 (ECB mode) encrypted in UTF-8: " + Base16.encode(aes128enc));
			writeLine("AES-128 (ECB mode) decrypted in UTF-8: " + UTF8.bytesToText(aes128dec));
			writeLine("");
			
			/**
			* Test AES-192 with one official test vector and custom input.
			* Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
			*/
			var aes192tvk:Array = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
			var aes192tvt:Array = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
			var aes192tve:Array = AES.encrypt(aes192tvk, aes192tvt); // No padding needed.
			var aes192tvd:Array = AES.decrypt(aes192tvk, aes192tve); // No padding needed.
			//
			var aes192iv:Array = UTF8.textToBytes("1234567890123456");
			var aes192key:Array = UTF8.textToBytes("123456789012345678901234");
			var aes192enc:Array = AES.encrypt(aes192key, PKCS7.pad(utf8Bytes, 16), OperationMode.CBC, aes192iv); // Encrypt in CBC mode. Needs padding.
			var aes192dec:Array = PKCS7.unpad(AES.decrypt(aes192key, aes192enc, OperationMode.CBC, aes192iv)); // Decrypt in CBC mode. Needs unpadding.
			//
			writeLine("AES-192 otv encrypted is ok: " + (Base16.encode(aes192tve) == "dda97ca4864cdfe06eaf70a0ec0d7191"));
			writeLine("AES-192 otv decrypted is ok: " + (Base16.encode(aes192tvd) == "00112233445566778899aabbccddeeff"));
			writeLine("AES-192 (CBC mode) encrypted in UTF-8: " + Base16.encode(aes192enc));
			writeLine("AES-192 (CBC mode) decrypted in UTF-8: " + UTF8.bytesToText(aes192dec));
			writeLine("");
			
			/**
			* Test AES-256 with one official test vector and custom input.
			* Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
			*/
			var aes256tvk:Array = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
			var aes256tvt:Array = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
			var aes256tve:Array = AES.encrypt(aes256tvk, aes256tvt); // None mode, no padding.
			var aes256tvd:Array = AES.decrypt(aes256tvk, aes256tve); // None mode, no padding.
			//
			var aes256iv:Array = UTF8.textToBytes("1234567890123456");
			var aes256key:Array = UTF8.textToBytes("12345678901234561234567890123456");
			var aes256enc:Array = AES.encrypt(aes256key, PKCS7.pad(utf8Bytes, 16), OperationMode.CTR, aes256iv); // Encrypt in CTR mode. Needs padding.
			var aes256dec:Array = PKCS7.unpad(AES.decrypt(aes256key, aes256enc, OperationMode.CTR, aes256iv)); // Decrypt in CTR mode. Needs unpadding.
			//
			writeLine("AES-256 otv encrypted is ok: " + (Base16.encode(aes256tve) == "8ea2b7ca516745bfeafc49904b496089"));
			writeLine("AES-256 otv decrypted is ok: " + (Base16.encode(aes256tvd) == "00112233445566778899aabbccddeeff"));
			writeLine("AES-256 (CTR mode) encrypted in UTF-8: " + Base16.encode(aes256enc));
			writeLine("AES-256 (CTR mode) decrypted in UTF-8: " + UTF8.bytesToText(aes256dec));
			writeLine("");
			
			/**
			* Print timing results.
			*/
			var end:Number = getTimer();
			writeLine("All this took: " + (end - start) + " milliseconds.");
		} 
		catch (e:Error)
		{
			writeLine(e.message);
		}
		
		/**
		* Show results.
		*/
		_root.console.text = this.output;
		
	}

}
