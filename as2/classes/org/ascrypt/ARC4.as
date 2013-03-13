/**
* Encrypts and decrypts data with an Alleged RC4 algorithm.
* <br/><br/>ARC4 is a stream cipher that operates on any block size and key sizes of 40 - 128 bits.
* @author Mika Palmu
*/
class org.ascrypt.ARC4
{
	/**
	* Private error messages constants of the class.
	*/
	private static var ERROR_KEY:String = "Invalid key size. Key size needs to be 40 - 128 bits.\n";
	private static var ERROR_INIT:String = "Boolean value init needs to be either true or false.\n";
	
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
	public static function encrypt(key:Array, bytes:Array, init:Boolean):Array
	{
		check(key, init);
		return core(key, bytes, init);
	}
	
	/**
	* Decrypts bytes with the specified key.
	* @param key An array of ASCII or UTF-8 bytes.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @param init Init the state with the key.
	* @return An array of decrypted bytes.
	*/
	public static function decrypt(key:Array, bytes:Array, init:Boolean):Array
	{
		check(key, init);
		return core(key, bytes, init);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function core(k:Array, b:Array, n:Boolean):Array
	{
		if (n) init(k);
		var r:Array = [];
		var bl:Number = b.length;
		var l:Number = 0, j:Number = 0;
		var v:Number, t:Number, x:Number;
		for (var i:Number = 0; i < bl; i++)
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
	private static function init(k:Array):Void
	{
		var l:Number = k.length;
		var t:Number, c:Number = 0;
		for (var i:Number = 0; i < 256; i++)
		{
			mkey[i] = k[(i % l)];
			sbox[i] = i;
		}
		for (var j:Number = 0; j < 256; j++)
		{
			c = (c + sbox[j] + mkey[j]) % 256;
			t = sbox[j]; 
			sbox[j] = sbox[c]; 
			sbox[c] = t;
		}
	}
	private static function check(k:Array, i:Boolean):Void
	{
		var kl:Number = k.length;
		if (i == undefined || i == null) throw new Error(ERROR_INIT);
		if (kl < 5 || kl > 16) throw new Error(ERROR_KEY);
	}
	
}
