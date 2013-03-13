package org.ascrypt
{
	/**
	* Encrypts and decrypts data with an Alleged RC4 algorithm.
	* <br/><br/>ARC4 is a stream cipher that operates on any block size and key sizes of 40 - 128 bits.
	* @author Mika Palmu
	*/
	public class ARC4
	{
		/**
		* Private error messages constants of the class.
		*/
		private static const ERROR_KEY:String = "Invalid key size. Key size needs to be 40 - 128 bits.\n";
		
		/**
		* Private properties of the class.
		*/
		private static var sbox:Array = [];
		private static var mkey:Array = [];
		
		/**
		* Encrypts bytes with the specified key.
		* @param key An array of ASCII or UTF-8 bytes.
		* @param bytes An array of ASCII or UTF-8 bytes.
		* @param init Init the state with the key.
		* @return An array of encrypted bytes.
		*/
		public static function encrypt(key:Array, bytes:Array, init:Boolean = true):Array
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
		public static function decrypt(key:Array, bytes:Array, init:Boolean = true):Array
		{
			check(key);
			return core(key, bytes, init);
		}
		
		/**
		* Private methods of the class.
		*/
		private static function core(k:Array, b:Array, n:Boolean):Array
		{
			if (n) init(k);
			var r:Array = [];
			var l:int = 0, j:int = 0;
			var v:int, t:int, x:int;
			for (var i:int = 0; i < b.length; i++)
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
		private static function init(k:Array):void
		{
			var l:int = k.length;
			var t:int, c:int = 0;
			for (var i:int = 0; i < 256; i++)
			{
				mkey[i] = k[(i % l)];
				sbox[i] = i;
			}
			for (var j:int = 0; j < 256; j++)
			{
				c = (c + sbox[j] + mkey[j]) % 256;
				t = sbox[j]; 
				sbox[j] = sbox[c]; 
				sbox[c] = t;
			}
		}
		private static function check(k:Array):void
		{
			var kl:int = k.length;
			if (kl < 5 || kl > 16) throw Error(ERROR_KEY);
		}
		
	}
	
}
