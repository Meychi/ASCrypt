package org.ascrypt.utilities
{
	/**
	* Encrypts and decrypts data in electronic codebook (ECB) confidentiality mode.
	* @author Mika Palmu
	*/
	public class ECB
	{
		/**
		* Encrypts bytes with the specified key.
		* @param key An array of key bytes.
		* @param bytes An array of input bytes.
		* @param size The block size of the cipher.
		* @param crypt The encryption function.
		* @return An array of ECB mode encrypted bytes.
		*/
		public static function encrypt(key:Array, bytes:Array, size:Number, encrypt:Function):Array
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
		public static function decrypt(key:Array, bytes:Array, size:Number, decrypt:Function):Array
		{
			return core(key, bytes, size, decrypt);
		}
		
		/**
		* Private static methods of the class.
		*/
		private static function core(k:Array, b:Array, s:Number, c:Function):Array
		{
			var r:Array = [];
			var l:int = b.length;
			for (var i:int = 0; i < l; i += s)
			{
				r = r.concat(c(k, b.slice(i, i + s)));
			}
			return r;
		}
		
	}
	
}
