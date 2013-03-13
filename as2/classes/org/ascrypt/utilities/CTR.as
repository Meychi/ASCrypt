/**
* Encrypts and decrypts data in counter (CTR) confidentiality mode.
* @author Mika Palmu
*/
class org.ascrypt.utilities.CTR
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
	public static function encrypt(key:Array, bytes:Array, size:Number, encrypt:Function, iv:Array):Array
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
	public static function decrypt(key:Array, bytes:Array, size:Number, encrypt:Function, iv:Array):Array
	{
		return core(key, bytes, size, encrypt, iv);
	}
	
	/**
	* Private static methods of the class.
	*/
	private static function core(k:Array, b:Array, s:Number, c:Function, v:Array):Array
	{
		var bl:Number = b.length;
		var e:Array = [], x:Array = v.concat();
		for (var i:Number = 0; i < bl; i += s)
		{
			e = c(k, x);
			for (var j:Number = 0; j < s; j++)
			{
				b[i + j] ^= e[j];
			}
			for (var l:Number = s - 1; l >= 0; --l)
			{
				x[l]++;
				if (x[l] != 0) break;
			}
		}
		return b;
	}
	
}
