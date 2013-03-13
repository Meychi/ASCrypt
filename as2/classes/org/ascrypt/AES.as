import org.ascrypt.common.*;
import org.ascrypt.utilities.*;

/**
* Encrypts and decrypts data with AES-128/192/256 algorithm.
* <br/><br/>AES is a block cipher that operates on a fixed block size of 128 bits and key sizes of 128, 192 or 256 bits. Supported modes are ECB, CBC, CTR or NONE.
* @author Mika Palmu
*/
class org.ascrypt.AES
{
	/**
	* Private error messages of the class.
	*/
	private static var ERROR_KEY:String = "Invalid key size. Key size needs to be either 128, 192 or 256 bits.\n";
	private static var ERROR_MODE:String = "Invalid mode of operation. Supported modes are ECB, CBC, CTR or NONE.\n";
	private static var ERROR_BLOCK:String = "Invalid block size. Block size is fixed at 128 bits.\n";
	
	/**
	* Private properties of the class.
	*/
	private static var xtime:Array;
	private static var isbox:Array;
	private static var isrtab:Array;
	private static var srtab:Array = [0x00, 0x05, 0x0a, 0x0f, 0x04, 0x09, 0x0e, 0x03, 0x08, 0x0d, 0x02, 0x07, 0x0c, 0x01, 0x06, 0x0b];
	private static var sbox:Array = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
	
	/**
	* Encrypts bytes with the specified key and IV.
	* @param key An array of ASCII or UTF-8 key bytes.
	* @param bytes An array of ASCII or UTF-8 input bytes.
	* @param mode The selected mode of operation.
	* @param iv An array of init vector bytes.
	* @return An array of encrypted bytes.
	*/
	public static function encrypt(key:Array, bytes:Array, mode:String, iv:Array):Array
	{
		check(key, bytes);
		if (!mode) mode = "ecb";
		var k:Array = key.concat();
		var b:Array = bytes.concat();
		init(); ek(k); // Initialize...
		switch (mode.toLowerCase()) 
		{
			case OperationMode.ECB : return ECB.encrypt(k, b, 16, ie);
			case OperationMode.CBC : return CBC.encrypt(k, b, 16, ie, iv.concat());
			case OperationMode.CTR : return CTR.encrypt(k, b, 16, ie, iv.concat());
			case OperationMode.NONE : return ie(k, b); // Encrypt in core more...
			default : throw new Error(ERROR_MODE);
		}
	}
	
	/**
	* Decrypts bytes with the specified key and IV.
	* @param key An array of ASCII or UTF-8 key bytes.
	* @param text An array of ASCII or UTF-8 input bytes.
	* @param mode The selected mode of operation.
	* @param iv An array of init vector bytes.
	* @return An array of decrypted bytes.
	*/
	public static function decrypt(key:Array, bytes:Array, mode:String, iv:Array):Array
	{
		check(key, bytes);
		if (!mode) mode = "ecb";
		var k:Array = key.concat();
		var b:Array = bytes.concat();
		init(); ek(k); // Initialize...
		switch (mode.toLowerCase())
		{
			case OperationMode.ECB : return ECB.decrypt(k, b, 16, id);
			case OperationMode.CBC : return CBC.decrypt(k, b, 16, id, iv.concat());
			case OperationMode.CTR : return CTR.decrypt(k, b, 16, ie, iv.concat());
			case OperationMode.NONE : return id(k, b); // Decrypt in core more...
			default : throw new Error(ERROR_MODE);
		}
	}
	
	/**
	* Private methods of the class.
	*/
	private static function init():Void
	{
		isrtab = new Array(16);
		isbox = new Array(256);
		xtime = new Array(256);
		for (var i:Number = 0; i < 256; i++) isbox[sbox[i]] = i;
		for (var j:Number = 0; j < 16; j++) isrtab[srtab[j]] = j;
		for (var k:Number = 0; k < 128; k++)
		{
			xtime[k] = k << 1;
			xtime[128 + k] = (k << 1) ^ 0x1b;
		}
	}
	private static function ek(k:Array):Void
	{
		var kl:Number = k.length;
		var ks:Number, rcon:Number = 1;
		switch (kl)
		{
			case 16: ks = 16 * 11; break;
			case 24: ks = 16 * 13; break;
			case 32: ks = 16 * 15; break;
		}
		for (var i:Number = kl; i < ks; i += 4) 
		{
			var t:Array = k.slice(i - 4, i);
			if (i % kl == 0) 
			{
				t = [sbox[t[1]] ^ rcon, sbox[t[2]], sbox[t[3]], sbox[t[0]]];
				if ((rcon <<= 1) >= 256) rcon ^= 0x11b;
			}
			else if ((kl > 24) && (i % kl == 16))
			{
				t = [sbox[t[0]], sbox[t[1]], sbox[t[2]], sbox[t[3]]];
			}      
			for (var j:Number = 0; j < 4; j++)
			{
				k[i + j] = k[i + j - kl] ^ t[j];
			}
		}
	}
	private static function ie(k:Array, ob:Array):Array
	{
		var b:Array = ob.concat();
		var i:Number, l:Number = k.length;
		ark(b, k.slice(0, 16));
		for (i = 16; i < l - 16; i += 16)
		{
			sb(b, sbox); sr(b, srtab); mc(b);
			ark(b, k.slice(i, i + 16));
		}
		sb(b, sbox); sr(b, srtab);
		ark(b, k.slice(i, i + 16));
		return b;
	}
	private static function id(k:Array, ob:Array):Array
	{
		var b:Array = ob.concat();
		var i:Number, l:Number = k.length;
		ark(b, k.slice(l - 16, l));
		sr(b, isrtab); sb(b, isbox);
		for(i = l - 32; i >= 16; i -= 16)
		{
			ark(b, k.slice(i, i + 16)); mci(b);
			sr(b, isrtab); sb(b, isbox);
		}
		ark(b, k.slice(0, 16));
		return b;
	}
	private static function sb(s:Array, b:Array):Void 
	{
		for (var i:Number = 0; i < 16; i++) s[i] = b[s[i]];
	}
	private static function ark(s:Array, r:Array):Void 
	{
		for (var i:Number = 0; i < 16; i++) s[i] ^= r[i];
	}
	private static function sr(s:Array, t:Array):Void
	{
		var h:Array = s.concat();
		for (var i:Number = 0; i < 16; i++) s[i] = h[t[i]];
	}
	private static function mc(s:Array):Void 
	{
		for (var i:Number = 0; i < 16; i += 4)
		{
			var s0:Number = s[i + 0], s1:Number = s[i + 1];
			var s2:Number = s[i + 2], s3:Number = s[i + 3];
			var h:Number = s0 ^ s1 ^ s2 ^ s3;
			s[i + 0] ^= h ^ xtime[s0 ^ s1];
			s[i + 1] ^= h ^ xtime[s1 ^ s2];
			s[i + 2] ^= h ^ xtime[s2 ^ s3];
			s[i + 3] ^= h ^ xtime[s3 ^ s0];
		}
	}
	private static function mci(s:Array):Void 
	{
		for (var i:Number = 0; i < 16; i += 4) 
		{
			var s0:Number = s[i + 0], s1:Number = s[i + 1];
			var s2:Number = s[i + 2], s3:Number = s[i + 3];
			var h:Number = s0 ^ s1 ^ s2 ^ s3;
			var xh:Number = xtime[h];
			var h1:Number = xtime[xtime[xh ^ s0 ^ s2]] ^ h;
			var h2:Number = xtime[xtime[xh ^ s1 ^ s3]] ^ h;
			s[i + 0] ^= h1 ^ xtime[s0 ^ s1];
			s[i + 1] ^= h2 ^ xtime[s1 ^ s2];
			s[i + 2] ^= h1 ^ xtime[s2 ^ s3];
			s[i + 3] ^= h2 ^ xtime[s3 ^ s0];
		}
	}
	private static function check(k:Array, b:Array):Void
	{
		var kl:Number = k.length;
		if (kl != 16 && kl != 24 && kl != 32) throw new Error(ERROR_KEY);
		if (b.length % 16 != 0) throw new Error(ERROR_BLOCK);
	}
	
}
