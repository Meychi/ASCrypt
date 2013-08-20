package org.ascrypt.utilities;

/**
* Encrypts and decrypts data in electronic codebook (ECB) confidentiality mode.
* @author Mika Palmu
*/
class ECB
{
	/**
	* Encrypts bytes with the specified key.
	* @param key An array of key bytes.
	* @param bytes An array of input bytes.
	* @param size The block size of the cipher.
	* @param crypt The encryption function.
	* @return An array of ECB mode encrypted bytes.
	*/
	public static inline function encrypt(key:Array<Int>, bytes:Array<Int>, size:Int, encrypt:Dynamic):Array<Int>
	{
		return core(key, bytes, size, encrypt);
	}
	
	/**
	* Decrypts bytes with the specified key.
	* @param key An array of key bytes.
	* @param bytes An array of input bytes.
	* @param size The block size of the cipher.
	* @param decrypt The decryption function.
	* @return An array of ECB mode decrypted bytes.
	*/
	public static inline function decrypt(key:Array<Int>, bytes:Array<Int>, size:Int, decrypt:Dynamic):Array<Int>
	{
		return core(key, bytes, size, decrypt);
	}
	
	/**
	* Private static methods of the class.
	*/
	private static inline function core(k:Array<Int>, b:Array<Int>, s:Int, c:Dynamic):Array<Int>
	{
		var r:Array<Int> = [];
		var l:Int = b.length;
		var i:Int = 0;
		while (i < l)
		{
			r = r.concat(c(k, b.slice(i, i + s)));
			i += s;
		}
		return r;
	}
	
}

