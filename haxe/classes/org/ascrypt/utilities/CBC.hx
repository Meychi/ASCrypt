package org.ascrypt.utilities;

/**
* Encrypts and decrypts data in cipher-block chaining (CBC) confidentiality mode.
* @author Mika Palmu
*/
class CBC
{
	/**
	* Encrypts bytes with the specified key and IV.
	* @param key An array of key bytes.
	* @param bytes An array of input bytes.
	* @param size The block size of the cipher.
	* @param encrypt The encryption function to use.
	* @param iv An array of init vector bytes.
	* @return An array of CBC mode encrypted bytes.
	*/
	public static inline function encrypt(key:Array<Int>, bytes:Array<Int>, size:Int, encrypt:Dynamic, iv:Array<Int>):Array<Int>
	{
		var r:Array<Int> = [];
		var l:Int = bytes.length;
		var i:Int = 0;
		while (i < l)
		{
			for (j in 0...size) bytes[i + j] ^= iv[j];
			r = r.concat(encrypt(key, bytes.slice(i, i + size)));
			iv = r.slice(i, i + size);
			i += size;
		}
		return r;
	}
	
	/**
	* Decrypts bytes with the specified key and IV.
	* @param key An array of key bytes.
	* @param bytes An array of input bytes.
	* @param size The block size of the cipher.
	* @param decrypt The decryption function to use.
	* @param iv An array of init vector bytes.
	* @return An array of CBC mode decrypted bytes.
	*/
	public static inline function decrypt(key:Array<Int>, bytes:Array<Int>, size:Int, decrypt:Dynamic, iv:Array<Int>):Array<Int>
	{
		var l:Int = bytes.length;
		var t:Array<Int>, r:Array<Int> = [];
		var i:Int = 0;
		while (i < l)
		{
			t = bytes.slice(i, i + size);
			r = r.concat(decrypt(key, t));
			for (j in 0...size) r[i + j] ^= iv[j];
			iv = t.slice(0, size);
			i += size;
		}
		return r;
	}
	
}
