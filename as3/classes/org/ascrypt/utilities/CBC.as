package org.ascrypt.utilities 
{
	/**
	* Encrypts and decrypts data in cipher-block chaining (CBC) confidentiality mode.
	* @author Mika Palmu
	*/
	public class CBC
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
		public static function encrypt(key:Array, bytes:Array, size:int, encrypt:Function, iv:Array):Array
		{
			var r:Array = [];
			var l:int = bytes.length;
			for (var i:int = 0; i < l; i += size)
			{
				for (var j:int = 0; j < size; j++)
				{
					bytes[i + j] ^= iv[j];
				}
				r = r.concat(encrypt(key, bytes.slice(i, i + size)));
				iv = r.slice(0, size);
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
		public static function decrypt(key:Array, bytes:Array, size:int, decrypt:Function, iv:Array):Array
		{
			var l:int = bytes.length;
			var t:Array, r:Array = [];
			for (var i:int = 0; i < l; i += size)
			{
				t = bytes.slice(i, i + size);
				r = r.concat(decrypt(key, t));
				for (var j:int = 0; j < size; j++)
				{
					r[i + j] ^= iv[j];
				}
				iv = t.slice(0, size);
			}
			return r;
		}
		
	}
	
}
