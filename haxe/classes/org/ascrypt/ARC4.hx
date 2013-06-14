package org.ascrypt;

/**
* Encrypts and decrypts data with an Alleged RC4 algorithm.
* ARC4 is a stream cipher that operates on any block size and key sizes of 40 - 128 bits.
* @author Mika Palmu
*/
class ARC4
{
	/**
	* Private properties of the class.
	*/
	private static var sbox:Array<Int> = [];
	private static var mkey:Array<Int> = [];
	
	/**
	* Private error messages constants of the class.
	*/
	private static var ERROR_KEY:String = "Invalid key size. Key size needs to be 40 - 128 bits.\n";
	
	/**
	* Encrypts bytes with the specified key.
	* @param key An array of ASCII or UTF-8 bytes.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @param init Init the state with the key.
	* @return An array of encrypted bytes.
	*/
	public static function encrypt(key:Array<Int>, bytes:Array<Int>, init:Bool = true):Array<Int>
	{
		check(key);
		return core(key, bytes, init);
	}
	
	/**
	* Decrypts bytes with the specified key.
	* @param key An array of ASCII or UTF-8 bytes.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @param init Init the state with the key.
	* @return An array of decrypted bytes.
	*/
	public static function decrypt(key:Array<Int>, bytes:Array<Int>, init:Bool = true):Array<Int>
	{
		check(key);
		return core(key, bytes, init);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function core(k:Array<Int>, b:Array<Int>, n:Bool):Array<Int>
	{
		if (n) init(k);
		var r:Array<Int> = [];
		var l:Int = 0, j:Int = 0;
		var v:Int, t:Int, x:Int;
		for (i in 0...b.length)
		{
			l = (l + 1) % 256;
			j = (j + sbox[l]) % 256;
			t = sbox[l];
			sbox[l] = sbox[j];
			sbox[j] = t;
			x = (sbox[l] + sbox[j]) % 256;
			v = sbox[x];
			r[i] = b[i] ^ v;
		}
		return r;
	}
	private static function init(k:Array<Int>):Void
	{
		var l:Int = k.length;
		var t:Int, c:Int = 0;
		for (i in 0...256)
		{
			mkey[i] = k[(i % l)];
			sbox[i] = i;
		}
		for (j in 0...256)
		{
			c = (c + sbox[j] + mkey[j]) % 256;
			t = sbox[j]; 
			sbox[j] = sbox[c]; 
			sbox[c] = t;
		}
	}
	private static function check(k:Array<Int>):Void
	{
		var kl:Int = k.length;
		if (kl < 5 || kl > 16) throw ERROR_KEY;
	}
	
}
