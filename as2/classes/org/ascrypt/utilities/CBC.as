/**
* Encrypts and decrypts data in cipher-block chaining (CBC) confidentiality mode.
* @author Mika Palmu
*/
class org.ascrypt.utilities.CBC
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
	public static function encrypt(key:Array, bytes:Array, size:Number, encrypt:Function, iv:Array):Array
	{
		var r:Array = [];
		var l:Number = bytes.length;
		for (var i:Number = 0; i < l; i += size)
		{
			for (var j:Number = 0; j < size; j++)
			{
				bytes[i + j] ^= iv[j];
			}
			r = r.concat(encrypt(key, bytes.slice(i, i + size)));
			iv = r.slice(i, i + size);
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
	public static function decrypt(key:Array, bytes:Array, size:Number, decrypt:Function, iv:Array):Array
	{
		var t:Array, r:Array = [];
		var l:Number = bytes.length;
		for (var i:Number = 0; i < l; i += size)
		{
			t = bytes.slice(i, i + size);
			r = r.concat(decrypt(key, t));
			for (var j:Number = 0; j < size; j++) 
			{
				r[i + j] ^= iv[j];
			}
			iv = t.slice(0, size);
		}
		return r;
	}
	
}
