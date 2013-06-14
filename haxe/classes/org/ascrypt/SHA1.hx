package org.ascrypt;

import org.ascrypt.utilities.HMAC;
import org.ascrypt.utilities.UTIL;

/**
* Computes a SHA-1 checksum for the specified data.
* SHA-1 is a cryptographic hash function that computes a message digest of 160 bits.
* @author Mika Palmu
*/
class SHA1
{
	/**
	* Computes a SHA-1 checksum for the bytes.
	* @param bytes An array of bytes in any encoding.
	* @return An array of SHA-1 computed bytes.
	*/
	public static function compute(bytes:Array<Int>):Array<Int>
	{
		var b:Array<Int> = UTIL.pack(bytes, false);
		return UTIL.unpack(core(b, bytes.length * 8), false);
	}
	
	/**
	* Computes a HMAC-SHA-1 for the key and bytes.
	* @param key An array of bytes in any encoding.
	* @param bytes An array of bytes in any encoding.
	* @return An array of HMAC-SHA-1 hashed bytes.
	*/
	public static function computeHMAC(key:Array<Int>, bytes:Array<Int>):Array<Int>
	{
		return HMAC.compute(key, bytes, SHA1.compute, 64);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function core(x:Array<Int>, l:Int):Array<Int>
	{
		var w:Array<Int> = [];
		x[l >> 5] |= 0x80 << (24 - l % 32);
		x[((l + 64 >> 9) << 4) + 15] = l;
		var i:Int = 0, a:Int =  0x67452301;
		var b:Int = 0xEFCDAB89, c:Int = 0x98BADCFE;
		var d:Int = 0x10325476, e:Int = 0xC3D2E1F0;
		while (i < x.length)
		{
			var olda:Int = a; 
			var oldb:Int = b, oldc:Int = c; 
			var oldd:Int = d, olde:Int = e;
			for (j in 0...80)
			{
				if (j < 16) w[j] = x[i + j]; // TODO: || 0;
				else w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
				var t:Int = rol(a, 5) + ft(j, b, c, d) + e + w[j] + kt(j);
				e = d; d = c;
				c = rol(b, 30);
				b = a; a = t;
			}
			a += olda; b += oldb;
			c += oldc; d += oldd;
			e += olde;
			i += 16;
		}
		return [a, b, c, d, e];
	}
	private static function kt(t:Int):Int
	{
		return (t < 20) ? 0x5A827999 : (t < 40) ?  0x6ED9EBA1 : (t < 60) ? 0x8F1BBCDC : 0xCA62C1D6;
	}
	private static function ft(t:Int, b:Int, c:Int, d:Int):Int
	{
		if (t < 20) return (b & c) | ((~b) & d);
		if (t < 40) return b ^ c ^ d;
		if (t < 60) return (b & c) | (b & d) | (c & d);
		return b ^ c ^ d;
	}
	private static function rol(n:Int, c:Int):Int
	{
		return (n << c) | (n >>> (32 - c));
	}
	
}
