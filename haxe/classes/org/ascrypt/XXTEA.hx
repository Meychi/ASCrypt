package org.ascrypt;

import org.ascrypt.utilities.UTIL;

/**
* Encrypts and decrypts data with the XXTEA (Corrected Block TEA) algorithm.
* XXTEA is a block cipher that operates on variable-length blocks (multiple of 32 bits, minimum of 64 bits) and fixed key size of 128 bits.
* @author Mika Palmu
*/
class XXTEA
{
	/**
	* Private error messages of the class.
	*/
	private static var ERROR_KEY:String = "Invalid key size. Key size is fixed at 128 bits.\n";
	private static var ERROR_BLOCK:String = "Invalid block size. Minimum block size is 64 bits and the block size needs to be multiple of 32 bits.\n";
	
	/**
	* Encrypts bytes with the specified key.
	* @param key An array of ASCII or UTF-8 key bytes.
	* @param bytes An array of ASCII or UTF-8 input bytes.
	* @return An array of encrypted bytes.
	*/
	public static function encrypt(key:Array<Int>, bytes:Array<Int>):Array<Int>
	{
		check(key, bytes);
		var h:Array<Int> = UTIL.pack(key);
		var v:Array<Int> = UTIL.pack(bytes);
		if (v.length <= 1) v[1] = 0; var n:Int = v.length;
		var z:Int = v[n - 1], y:Int = v[0], d:Int = 0x9E3779B9;
		var m:Int, e:Int, s:Int = 0, q:Int = Math.floor(6 + 52 / n);
		while (q-- > 0) 
		{
			s += d;
			e = s >>> 2 & 3;
			for (i in 0...n)
			{
				y = v[(i + 1) % n];
				m = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (s ^ y) + (h[i & 3 ^ e] ^ z);
				z = v[i] += m;
			}
		}
		return UTIL.unpack(v);
	}
	
	/**
	* Decrypts bytes with the specified key.
	* @param key An array of ASCII or UTF-8 key bytes.
	* @param bytes An array of ASCII or UTF-8 input bytes.
	* @return An array of decrypted bytes.
	*/
	public static function decrypt(key:Array<Int>, bytes:Array<Int>):Array<Int>
	{
		check(key, bytes);
		var h:Array<Int> = UTIL.pack(key);
		var v:Array<Int> = UTIL.pack(bytes);
		var n:Int = v.length, z:Int = v[n - 1], y:Int = v[0], d:Int = 0x9E3779B9;
		var m:Int, e:Int, q:Int = Math.floor(6 + 52 / n), s:Int = q * d;
		while (s != 0) 
		{
			e = s >>> 2 & 3;
			var i:Int = n - 1;
			while (i >= 0) 
			{
				z = v[i > 0 ? i - 1 : n - 1];
				m = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (s ^ y) + (h[i & 3 ^ e] ^ z);
				y = v[i] -= m;
				i--;
			}
			s -= d;
		}
		return UTIL.unpack(v);
	}
	
	/**
	* Private static methods of the class.
	*/
	private static inline function check(k:Array<Int>, b:Array<Int>):Void
	{
		if (k.length != 16) throw ERROR_KEY;
		if (b.length < 8 || b.length % 4 != 0) throw ERROR_BLOCK;
	}
	
}
