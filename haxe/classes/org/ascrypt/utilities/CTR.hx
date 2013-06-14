package org.ascrypt.utilities;

/**
* Encrypts and decrypts data in counter (CTR) confidentiality mode.
* @author Mika Palmu
*/
class CTR
{
	/**
	* Encrypts bytes with the specified key and IV.
	* @param key An array of key bytes.
	* @param bytes An array of input bytes.
	* @param size The block size of the cipher.
	* @param encrypt The encryption function to use.
	* @param iv An array of init vector bytes.
	* @return An array of CTR mode encrypted bytes.
	*/
	public static function encrypt(key:Array<Int>, bytes:Array<Int>, size:Int, encrypt:Dynamic, iv:Array<Int>):Array<Int>
	{
		return core(key, bytes, size, encrypt, iv);
	}
	
	/**
	* Decrypts bytes with the specified key and IV.
	* @param key An array of key bytes.
	* @param bytes An array of input bytes.
	* @param size The block size of the cipher.
	* @param encrypt The encryption function to use.
	* @param iv An array of init vector bytes.
	* @return An array of CTR mode decrypted bytes.
	*/
	public static function decrypt(key:Array<Int>, bytes:Array<Int>, size:Int, encrypt:Dynamic, iv:Array<Int>):Array<Int>
	{
		return core(key, bytes, size, encrypt, iv);
	}
	
	/**
	* Private static methods of the class.
	*/
	private static function core(k:Array<Int>, b:Array<Int>, s:Int, c:Dynamic, v:Array<Int>):Array<Int>
	{
		var bl:Int = b.length;
		var e:Array<Int> = [], x:Array<Int> = v.concat([]);
		var i:Int = 0;
		while (i < bl)
		{
			e = c(k, x);
			for (j in 0...s) b[i + j] ^= e[j];
			var l:Int = s - 1;
			while (l >= 0)
			{
				--l;
				x[l]++;
				if (x[l] != 0) break;
			}
			i += s;
		}
		return b;
	}
	
}
