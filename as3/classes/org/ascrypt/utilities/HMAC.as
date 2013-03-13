package org.ascrypt.utilities 
{
	/**
	* Computes a hash message authentication code (HMAC) with the specified hash function.
	* @author Mika Palmu
	*/
	public class HMAC
	{
		/**
		* Computes a HMAC with the specified hash function.
		* @param key An array of key bytes.
		* @param bytes An array of input bytes.
		* @param hash The hash function to use.
		* @param size The input size of the hash.
		* @return An array of HMAC bytes.
		*/
		public static function compute(key:Array, bytes:Array, hash:Function, size:int):Array
		{
			var hk:Array = key.concat();
			var ik:Array = [], ok:Array = [];
			if (key.length > size) hk = hash(key);
			while (hk.length < size) hk[hk.length] = 0;
			var hkl:int = hk.length; // lenght
			for (var i:int = 0; i < hkl; i++)
			{
				ik[i] = hk[i] ^ 0x36;
				ok[i] = hk[i] ^ 0x5c;
			}
			ik = ik.concat(bytes);
			ok = ok.concat(hash(ik));
			return hash(ok);
		}
		
	}
	
}
