package org.ascrypt;

import org.ascrypt.utilities.HMAC;
import org.ascrypt.utilities.UTIL;

/**
* Computes a SHA-256 checksum for the specified data.
* <br/><br/>SHA-256 is a cryptographic hash function that computes a message digest of 256 bits.
* @author Mika Palmu
*/
class SHA256
{
	/**
	* Computes a SHA-256 checksum for the bytes.
	* @param bytes An array of bytes in any encoding.
	* @return An array of SHA-256 computed bytes.
	*/
	public static function compute(bytes:Array<Int>):Array<Int>
	{
		var b:Array<Int> = UTIL.pack(bytes, false);
		return UTIL.unpack(core(b, bytes.length * 8), false);
	}
	
	/**
	* Computes a HMAC-SHA-256 for the key and bytes.
	* @param key An array of bytes in any encoding.
	* @param bytes An array of bytes in any encoding.
	* @return An array of HMAC-SHA-256 hashed bytes.
	*/
	public static function computeHMAC(key:Array<Int>, bytes:Array<Int>):Array<Int>
	{
		return HMAC.compute(key, bytes, SHA256.compute, 64);
	}
	
	#if (flash8 || js)
	
	/**
	* Private methods of the class.
	*/
	private static inline function core(m:Array<Int>, l:Int):Array<Int>
	{
		var a:Int, b:Int, c:Int, d:Int; 
		var e:Int, f:Int, g:Int, h:Int, i:Int = 0;
		var t1:Int, t2:Int, w:Array<Int> = new Array<Int>();
		var k:Array<Int> = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2];
		var r:Array<Int> = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
		m[l >> 5] |= 0x80 << (24 - l % 32);
		m[((l + 64 >> 9) << 4) + 15] = l;
		while (i < m.length)
		{
			a = r[0]; b = r[1]; c = r[2]; d = r[3];
			e = r[4]; f = r[5]; g = r[6]; h = r[7];
			for (j in 0...64)
			{
				if (j < 16) w[j] = m[j + i];
				else w[j] = add(add(add(g1256(w[j - 2]), w[j - 7]), g0256(w[j - 15])), w[j - 16]);
				t1 = add(add(add(add(h, s1256(e)), ch(e, f, g)), k[j]), w[j]);
				t2 = add(s0256(a), maj(a, b, c));
				h = g; g = f; f = e; e = add(d, t1);
				d = c; c = b; b = a; a = add(t1, t2);
			}
			r[0] = add(a, r[0]); r[1] = add(b, r[1]);
			r[2] = add(c, r[2]); r[3] = add(d, r[3]);
			r[4] = add(e, r[4]); r[5] = add(f, r[5]);
			r[6] = add(g, r[6]); r[7] = add(h, r[7]);
			i += 16;
		}
		return r;
	}
	private static inline function s(x:Int, n:Int):Int 
	{
		return (x >>> n) | (x << (32 - n));
	}
	private static inline function ch(x:Int, y:Int, z:Int):Int 
	{
		return ((x & y) ^ ((~x) & z));
	}
	private static inline function maj(x:Int, y:Int, z:Int):Int 
	{
		return ((x & y) ^ (x & z) ^ (y & z));
	}
	private static inline function s0256(x:Int):Int 
	{
		return (s(x, 2) ^ s(x, 13) ^ s(x, 22));
	}
	private static inline function s1256(x:Int):Int 
	{
		return (s(x, 6) ^ s(x, 11) ^ s(x, 25));
	}
	private static inline function g0256(x:Int):Int 
	{
		return (s(x, 7) ^ s(x, 18) ^ (x >>> 3));
	}
	private static inline function g1256(x:Int):Int 
	{
		return (s(x, 17) ^ s(x, 19) ^ (x >>> 10));
	}
	public static inline function add(one:Int, two:Int):Int
	{
		var l:Int = (one & 0xFFFF) + (two & 0xFFFF);
		var m:Int = (one >> 16) + (two >> 16) + (l >> 16);
		return (m << 16) | (l & 0xFFFF);
	}
	
	#else
	
	/**
	* Private constants of the class.
	*/
	private static var h:Array<Int> = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
	private static var k:Array<Int> = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	
	/**
	* Private methods of the class.
	*/
	private static inline function core(x:Array<Int>, l:Int):Array<Int>
	{
		x[l >> 5] |= 0x80 << (24 - l % 32);
		x[((l + 64 >> 9) << 4) + 15] = l;
		var i:Int = 0, w:Array<Int> = [];
		var a:Int = h[0], b:Int = h[1];
		var c:Int = h[2], d:Int = h[3];
		var e:Int = h[4], f:Int = h[5];
		var g:Int = h[6], h:Int = h[7];
		while (i < x.length)
		{
			var olda:Int = a, oldb:Int = b;
			var oldc:Int = c, oldd:Int = d;
			var olde:Int = e, oldf:Int = f;
			var oldg:Int = g, oldh:Int = h;
			for (j in 0...64)
			{
				if (j < 16) w[j] = x[i + j];
				else 
				{
					var s0:Int = rrol(w[j - 15], 7) ^ rrol(w[j - 15], 18) ^ (w[j - 15] >>> 3);
					var s1:Int = rrol(w[j - 2], 17) ^ rrol(w[j - 2], 19) ^ (w[j - 2] >>> 10);
					w[j] = w[j - 16] + s0 + w[j - 7] + s1;
				}
				var t2:Int = (rrol(a, 2) ^ rrol(a, 13) ^ rrol(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
				var t1:Int = h + (rrol(e, 6) ^ rrol(e, 11) ^ rrol(e, 25)) + ((e & f) ^ (g & ~e)) + k[j] + w[j];
				h = g; g = f; f = e; e = d + t1;
				d = c; c = b; b = a; a = t1 + t2;
			}
			a += olda; b += oldb; c += oldc; d += oldd;
			e += olde; f += oldf; g += oldg; h += oldh;
			i += 16;
		}
		return [a, b, c, d, e, f, g, h];
	}
	private static inline function rrol(n:Int, c:Int):Int
	{
		return (n << (32 - c)) | (n >>> c);
	}
	
	#end
	
}
