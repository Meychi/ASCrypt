(function () { "use strict";
var HxOverrides = function() { }
HxOverrides.__name__ = true;
HxOverrides.cca = function(s,index) {
	var x = s.charCodeAt(index);
	if(x != x) return undefined;
	return x;
}
HxOverrides.substr = function(s,pos,len) {
	if(pos != null && pos != 0 && len != null && len < 0) return "";
	if(len == null) len = s.length;
	if(pos < 0) {
		pos = s.length + pos;
		if(pos < 0) pos = 0;
	} else if(len < 0) len = s.length + len - pos;
	return s.substr(pos,len);
}
var Main = function() {
	this.log = "";
};
Main.__name__ = true;
Main.main = function() {
	var main = new Main();
	main.testAlgorithms();
}
Main.prototype = {
	testAlgorithms: function() {
		try {
			var start = this.getTimer();
			var input = "Hello to € World!";
			var pb = [1,2,3,4,5,6,7,8,9,10,11,12];
			var nb = [1,2,3,4,5,6,7,8,9,10,11,12];
			var pp = org.ascrypt.padding.PKCS7.pad(pb,8);
			var pu = org.ascrypt.padding.PKCS7.unpad(pp);
			this.writeLine("PKCS#7 padded: " + Std.string(pp));
			this.writeLine("PKCS#7 unpadded: " + Std.string(pu));
			this.writeLine("");
			var np = org.ascrypt.padding.ZEROS.pad(nb,8);
			var nu = org.ascrypt.padding.ZEROS.unpad(np);
			this.writeLine("Zero byte padded: " + Std.string(np));
			this.writeLine("Zero byte unpadded: " + Std.string(nu));
			this.writeLine("");
			var utf8Bytes = org.ascrypt.encoding.UTF8.textToBytes(input);
			var uleBytes = org.ascrypt.encoding.LittleEndian.textToBytes(input);
			var ubeBytes = org.ascrypt.encoding.BigEndian.textToBytes(input);
			this.writeLine("UTF-16 BE bytes: " + Std.string(ubeBytes));
			this.writeLine("UTF-16 LE bytes: " + Std.string(uleBytes));
			this.writeLine("UTF-8 bytes: " + Std.string(utf8Bytes));
			this.writeLine("");
			var b16utf8enc = org.ascrypt.Base16.encode(utf8Bytes);
			var b16utf8dec = org.ascrypt.Base16.decode(b16utf8enc);
			this.writeLine("Base16 encoded in UTF-8: " + b16utf8enc);
			this.writeLine("Base16 decoded in UTF-8: " + Std.string(b16utf8dec));
			this.writeLine("");
			var b64utf8enc = org.ascrypt.Base64.encode(utf8Bytes);
			var b64utf8dec = org.ascrypt.Base64.decode(b64utf8enc);
			this.writeLine("Base64 encoded in UTF-8: " + b64utf8enc);
			this.writeLine("Base64 decoded in UTF-8: " + Std.string(b64utf8dec));
			this.writeLine("");
			var guid1 = org.ascrypt.GUID.create();
			var guid2 = org.ascrypt.GUID.create();
			var guid3 = org.ascrypt.GUID.create();
			this.writeLine("Generated GUID 1: " + guid1);
			this.writeLine("Generated GUID 2: " + guid2);
			this.writeLine("Generated GUID 3: " + guid3);
			this.writeLine("");
			var r13enc = org.ascrypt.ROT13.encode(utf8Bytes);
			var r13dec = org.ascrypt.ROT13.decode(r13enc);
			this.writeLine("ROT13 encoded in UTF-8: " + org.ascrypt.encoding.UTF8.bytesToText(r13enc));
			this.writeLine("ROT13 decoded in UTF-8: " + org.ascrypt.encoding.UTF8.bytesToText(r13dec));
			this.writeLine("");
			var md5tv = org.ascrypt.MD5.compute([]);
			var md5utf8 = org.ascrypt.MD5.compute(utf8Bytes);
			var md5key = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var md5hmac = org.ascrypt.MD5.computeHMAC(md5key,utf8Bytes);
			this.writeLine("MD5 from otv is ok: " + Std.string(org.ascrypt.Base16.encode(md5tv) == "d41d8cd98f00b204e9800998ecf8427e"));
			this.writeLine("MD5 HMAC in UTF-8: " + org.ascrypt.Base16.encode(md5hmac));
			this.writeLine("MD5 in UTF-8: " + org.ascrypt.Base16.encode(md5utf8));
			this.writeLine("");
			var rmd160tv = org.ascrypt.RMD160.compute([]);
			var rmd160utf8 = org.ascrypt.RMD160.compute(utf8Bytes);
			var rmd160key = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var rmd160hmac = org.ascrypt.RMD160.computeHMAC(rmd160key,utf8Bytes);
			this.writeLine("RMD-160 from otv is ok: " + Std.string(org.ascrypt.Base16.encode(rmd160tv) == "9c1185a5c5e9fc54612808977ee8f548b2258d31"));
			this.writeLine("RMD-160 HMAC in UTF-8: " + org.ascrypt.Base16.encode(rmd160hmac));
			this.writeLine("RMD-160 in UTF-8: " + org.ascrypt.Base16.encode(rmd160utf8));
			this.writeLine("");
			var sha1tv = org.ascrypt.SHA1.compute([]);
			var sha1utf8 = org.ascrypt.SHA1.compute(utf8Bytes);
			var sha1key = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var sha1hmac = org.ascrypt.SHA1.computeHMAC(sha1key,utf8Bytes);
			this.writeLine("SHA-1 from otv is ok: " + Std.string(org.ascrypt.Base16.encode(sha1tv) == "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
			this.writeLine("SHA-1 HMAC in UTF-8: " + org.ascrypt.Base16.encode(sha1hmac));
			this.writeLine("SHA-1 in UTF-8: " + org.ascrypt.Base16.encode(sha1utf8));
			this.writeLine("");
			var sha256tv = org.ascrypt.SHA256.compute([]);
			var sha256utf8 = org.ascrypt.SHA256.compute(utf8Bytes);
			var sha256key = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var sha256hmac = org.ascrypt.SHA256.computeHMAC(sha256key,utf8Bytes);
			this.writeLine("SHA-256 from otv is ok: " + Std.string(org.ascrypt.Base16.encode(sha256tv) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
			this.writeLine("SHA-256 HMAC in UTF-8: " + org.ascrypt.Base16.encode(sha256hmac));
			this.writeLine("SHA-256 in UTF-8: " + org.ascrypt.Base16.encode(sha256utf8));
			this.writeLine("");
			var arc4tvk = org.ascrypt.Base16.decode("0123456789abcdef");
			var arc4tvt = org.ascrypt.Base16.decode("0123456789abcdef");
			var arc4tve = org.ascrypt.ARC4.encrypt(arc4tvk,arc4tvt);
			var arc4tvd = org.ascrypt.ARC4.decrypt(arc4tvk,arc4tve);
			var arc4key = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var arc4enc = org.ascrypt.ARC4.encrypt(arc4key,utf8Bytes);
			var arc4dec = org.ascrypt.ARC4.decrypt(arc4key,arc4enc);
			this.writeLine("ARC4 otv encrypted is ok: " + Std.string(org.ascrypt.Base16.encode(arc4tve) == "75b7878099e0c596"));
			this.writeLine("ARC4 otv decrypted is ok: " + Std.string(org.ascrypt.Base16.encode(arc4tvd) == "0123456789abcdef"));
			this.writeLine("ARC4 encrypted in UTF-8: " + org.ascrypt.Base16.encode(arc4enc));
			this.writeLine("ARC4 decrypted in UTF-8: " + org.ascrypt.encoding.UTF8.bytesToText(arc4dec));
			this.writeLine("");
			var xxttvk = org.ascrypt.Base16.decode("9e3779b99b9773e9b979379e6b695156");
			var xxttvt = org.ascrypt.Base16.decode("0102040810204080fffefcf8f0e0c080");
			var xxttve = org.ascrypt.XXTEA.encrypt(xxttvk,xxttvt);
			var xxttvd = org.ascrypt.XXTEA.decrypt(xxttvk,xxttve);
			var xxtkey = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var xxtenc = org.ascrypt.XXTEA.encrypt(xxtkey,org.ascrypt.padding.PKCS7.pad(utf8Bytes,4));
			var xxtdec = org.ascrypt.padding.PKCS7.unpad(org.ascrypt.XXTEA.decrypt(xxtkey,xxtenc));
			this.writeLine("XXTEA otv encrypted is ok: " + Std.string(org.ascrypt.Base16.encode(xxttve) == "01b815fd2e4894d13555da434c9d868a"));
			this.writeLine("XXTEA otv decrypted is ok: " + Std.string(org.ascrypt.Base16.encode(xxttvd) == "0102040810204080fffefcf8f0e0c080"));
			this.writeLine("XXTEA encrypted in UTF-8: " + org.ascrypt.Base16.encode(xxtenc));
			this.writeLine("XXTEA decrypted in UTF-8: " + org.ascrypt.encoding.UTF8.bytesToText(xxtdec));
			this.writeLine("");
			var aes128tvk = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
			var aes128tvt = [0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255];
			var aes128tve = org.ascrypt.AES.encrypt(aes128tvk,aes128tvt);
			var aes128tvd = org.ascrypt.AES.decrypt(aes128tvk,aes128tve);
			var aes128key = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var aes128enc = org.ascrypt.AES.encrypt(aes128key,org.ascrypt.padding.PKCS7.pad(utf8Bytes,16));
			var aes128dec = org.ascrypt.padding.PKCS7.unpad(org.ascrypt.AES.decrypt(aes128key,aes128enc));
			this.writeLine("AES-128 otv encrypted is ok: " + Std.string(org.ascrypt.Base16.encode(aes128tve) == "69c4e0d86a7b0430d8cdb78070b4c55a"));
			this.writeLine("AES-128 otv decrypted is ok: " + Std.string(org.ascrypt.Base16.encode(aes128tvd) == "00112233445566778899aabbccddeeff"));
			this.writeLine("AES-128 (ECB mode) encrypted in UTF-8: " + org.ascrypt.Base16.encode(aes128enc));
			this.writeLine("AES-128 (ECB mode) decrypted in UTF-8: " + org.ascrypt.encoding.UTF8.bytesToText(aes128dec));
			this.writeLine("");
			var aes192tvk = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23];
			var aes192tvt = [0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255];
			var aes192tve = org.ascrypt.AES.encrypt(aes192tvk,aes192tvt);
			var aes192tvd = org.ascrypt.AES.decrypt(aes192tvk,aes192tve);
			var aes192iv = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var aes192key = org.ascrypt.encoding.UTF8.textToBytes("123456789012345678901234");
			var aes192enc = org.ascrypt.AES.encrypt(aes192key,org.ascrypt.padding.PKCS7.pad(utf8Bytes,16),org.ascrypt.common.OperationMode.CBC,aes192iv);
			var aes192dec = org.ascrypt.padding.PKCS7.unpad(org.ascrypt.AES.decrypt(aes192key,aes192enc,org.ascrypt.common.OperationMode.CBC,aes192iv));
			this.writeLine("AES-192 otv encrypted is ok: " + Std.string(org.ascrypt.Base16.encode(aes192tve) == "dda97ca4864cdfe06eaf70a0ec0d7191"));
			this.writeLine("AES-192 otv decrypted is ok: " + Std.string(org.ascrypt.Base16.encode(aes192tvd) == "00112233445566778899aabbccddeeff"));
			this.writeLine("AES-192 (CBC mode) encrypted in UTF-8: " + org.ascrypt.Base16.encode(aes192enc));
			this.writeLine("AES-192 (CBC mode) decrypted in UTF-8: " + org.ascrypt.encoding.UTF8.bytesToText(aes192dec));
			this.writeLine("");
			var aes256tvk = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
			var aes256tvt = [0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255];
			var aes256tve = org.ascrypt.AES.encrypt(aes256tvk,aes256tvt);
			var aes256tvd = org.ascrypt.AES.decrypt(aes256tvk,aes256tve);
			var aes256iv = org.ascrypt.encoding.UTF8.textToBytes("1234567890123456");
			var aes256key = org.ascrypt.encoding.UTF8.textToBytes("12345678901234561234567890123456");
			var aes256enc = org.ascrypt.AES.encrypt(aes256key,org.ascrypt.padding.PKCS7.pad(utf8Bytes,16),org.ascrypt.common.OperationMode.CTR,aes256iv);
			var aes256dec = org.ascrypt.padding.PKCS7.unpad(org.ascrypt.AES.decrypt(aes256key,aes256enc,org.ascrypt.common.OperationMode.CTR,aes256iv));
			this.writeLine("AES-256 otv encrypted is ok: " + Std.string(org.ascrypt.Base16.encode(aes256tve) == "8ea2b7ca516745bfeafc49904b496089"));
			this.writeLine("AES-256 otv decrypted is ok: " + Std.string(org.ascrypt.Base16.encode(aes256tvd) == "00112233445566778899aabbccddeeff"));
			this.writeLine("AES-256 (CTR mode) encrypted in UTF-8: " + org.ascrypt.Base16.encode(aes256enc));
			this.writeLine("AES-256 (CTR mode) decrypted in UTF-8: " + org.ascrypt.encoding.UTF8.bytesToText(aes256dec));
			this.writeLine("");
			var end = this.getTimer();
			this.writeLine("All this took: " + (end - start) + " milliseconds.");
			console.log(this.log);
		} catch( msg ) {
			this.writeLine("Error: " + Std.string(msg));
		}
	}
	,getTimer: function() {
		return new Date().getTime();
	}
	,writeLine: function(msg) {
		this.log += msg + "\n";
	}
}
var Std = function() { }
Std.__name__ = true;
Std.string = function(s) {
	return js.Boot.__string_rec(s,"");
}
Std.parseInt = function(x) {
	var v = parseInt(x,10);
	if(v == 0 && (HxOverrides.cca(x,1) == 120 || HxOverrides.cca(x,1) == 88)) v = parseInt(x);
	if(isNaN(v)) return null;
	return v;
}
var StringTools = function() { }
StringTools.__name__ = true;
StringTools.hex = function(n,digits) {
	var s = "";
	var hexChars = "0123456789ABCDEF";
	do {
		s = hexChars.charAt(n & 15) + s;
		n >>>= 4;
	} while(n > 0);
	if(digits != null) while(s.length < digits) s = "0" + s;
	return s;
}
var js = {}
js.Boot = function() { }
js.Boot.__name__ = true;
js.Boot.__string_rec = function(o,s) {
	if(o == null) return "null";
	if(s.length >= 5) return "<...>";
	var t = typeof(o);
	if(t == "function" && (o.__name__ || o.__ename__)) t = "object";
	switch(t) {
	case "object":
		if(o instanceof Array) {
			if(o.__enum__) {
				if(o.length == 2) return o[0];
				var str = o[0] + "(";
				s += "\t";
				var _g1 = 2, _g = o.length;
				while(_g1 < _g) {
					var i = _g1++;
					if(i != 2) str += "," + js.Boot.__string_rec(o[i],s); else str += js.Boot.__string_rec(o[i],s);
				}
				return str + ")";
			}
			var l = o.length;
			var i;
			var str = "[";
			s += "\t";
			var _g = 0;
			while(_g < l) {
				var i1 = _g++;
				str += (i1 > 0?",":"") + js.Boot.__string_rec(o[i1],s);
			}
			str += "]";
			return str;
		}
		var tostr;
		try {
			tostr = o.toString;
		} catch( e ) {
			return "???";
		}
		if(tostr != null && tostr != Object.toString) {
			var s2 = o.toString();
			if(s2 != "[object Object]") return s2;
		}
		var k = null;
		var str = "{\n";
		s += "\t";
		var hasp = o.hasOwnProperty != null;
		for( var k in o ) { ;
		if(hasp && !o.hasOwnProperty(k)) {
			continue;
		}
		if(k == "prototype" || k == "__class__" || k == "__super__" || k == "__interfaces__" || k == "__properties__") {
			continue;
		}
		if(str.length != 2) str += ", \n";
		str += s + k + " : " + js.Boot.__string_rec(o[k],s);
		}
		s = s.substring(1);
		str += "\n" + s + "}";
		return str;
	case "function":
		return "<function>";
	case "string":
		return o;
	default:
		return String(o);
	}
}
var org = {}
org.ascrypt = {}
org.ascrypt.AES = function() { }
org.ascrypt.AES.__name__ = true;
org.ascrypt.AES.encrypt = function(key,bytes,mode,iv) {
	if(mode == null) mode = "ecb";
	org.ascrypt.AES.check(key,bytes);
	var k = key.slice();
	var b = bytes.slice();
	org.ascrypt.AES.init();
	org.ascrypt.AES.ek(k);
	var _g = mode.toLowerCase();
	switch(_g) {
	case org.ascrypt.common.OperationMode.ECB:
		return org.ascrypt.utilities.ECB.encrypt(k,b,16,org.ascrypt.AES.ie);
	case org.ascrypt.common.OperationMode.CBC:
		return org.ascrypt.utilities.CBC.encrypt(k,b,16,org.ascrypt.AES.ie,iv.slice());
	case org.ascrypt.common.OperationMode.CTR:
		return org.ascrypt.utilities.CTR.encrypt(k,b,16,org.ascrypt.AES.ie,iv.slice());
	case org.ascrypt.common.OperationMode.NONE:
		return org.ascrypt.AES.ie(k,b);
	default:
		throw org.ascrypt.AES.ERROR_MODE;
	}
}
org.ascrypt.AES.decrypt = function(key,bytes,mode,iv) {
	if(mode == null) mode = "ecb";
	org.ascrypt.AES.check(key,bytes);
	var k = key.slice();
	var b = bytes.slice();
	org.ascrypt.AES.init();
	org.ascrypt.AES.ek(k);
	var _g = mode.toLowerCase();
	switch(_g) {
	case org.ascrypt.common.OperationMode.ECB:
		return org.ascrypt.utilities.ECB.decrypt(k,b,16,org.ascrypt.AES.id);
	case org.ascrypt.common.OperationMode.CBC:
		return org.ascrypt.utilities.CBC.decrypt(k,b,16,org.ascrypt.AES.id,iv.slice());
	case org.ascrypt.common.OperationMode.CTR:
		return org.ascrypt.utilities.CTR.decrypt(k,b,16,org.ascrypt.AES.ie,iv.slice());
	case org.ascrypt.common.OperationMode.NONE:
		return org.ascrypt.AES.id(k,b);
	default:
		throw org.ascrypt.AES.ERROR_MODE;
	}
}
org.ascrypt.AES.init = function() {
	org.ascrypt.AES.isrtab = new Array();
	org.ascrypt.AES.isbox = new Array();
	org.ascrypt.AES.xtime = new Array();
	var _g = 0;
	while(_g < 256) {
		var i = _g++;
		org.ascrypt.AES.isbox[org.ascrypt.AES.sbox[i]] = i;
	}
	var _g = 0;
	while(_g < 16) {
		var j = _g++;
		org.ascrypt.AES.isrtab[org.ascrypt.AES.srtab[j]] = j;
	}
	var _g = 0;
	while(_g < 128) {
		var k = _g++;
		org.ascrypt.AES.xtime[k] = k << 1;
		org.ascrypt.AES.xtime[128 + k] = k << 1 ^ 27;
	}
}
org.ascrypt.AES.sb = function(s,b) {
	var _g = 0;
	while(_g < 16) {
		var i = _g++;
		s[i] = b[s[i]];
	}
}
org.ascrypt.AES.ark = function(s,r) {
	var _g = 0;
	while(_g < 16) {
		var i = _g++;
		s[i] ^= r[i];
	}
}
org.ascrypt.AES.sr = function(s,t) {
	var h = s.slice();
	var _g = 0;
	while(_g < 16) {
		var i = _g++;
		s[i] = h[t[i]];
	}
}
org.ascrypt.AES.ek = function(k) {
	var kl = k.length;
	var ks = 0, rcon = 1;
	switch(kl) {
	case 16:
		ks = 176;
		break;
	case 24:
		ks = 208;
		break;
	case 32:
		ks = 240;
		break;
	}
	var i = kl;
	while(i < ks) {
		var t = k.slice(i - 4,i);
		if(i % kl == 0) {
			t = [org.ascrypt.AES.sbox[t[1]] ^ rcon,org.ascrypt.AES.sbox[t[2]],org.ascrypt.AES.sbox[t[3]],org.ascrypt.AES.sbox[t[0]]];
			if((rcon <<= 1) >= 256) rcon ^= 283;
		} else if(kl > 24 && i % kl == 16) t = [org.ascrypt.AES.sbox[t[0]],org.ascrypt.AES.sbox[t[1]],org.ascrypt.AES.sbox[t[2]],org.ascrypt.AES.sbox[t[3]]];
		var j = 0;
		while(j < 4) {
			k[i + j] = k[i + j - kl] ^ t[j];
			j++;
		}
		i += 4;
	}
}
org.ascrypt.AES.ie = function(k,ob) {
	var b = ob.slice();
	var i = 16, l = k.length;
	org.ascrypt.AES.ark(b,k.slice(0,16));
	while(i < l - 16) {
		org.ascrypt.AES.sb(b,org.ascrypt.AES.sbox);
		org.ascrypt.AES.sr(b,org.ascrypt.AES.srtab);
		org.ascrypt.AES.mc(b);
		org.ascrypt.AES.ark(b,k.slice(i,i + 16));
		i += 16;
	}
	org.ascrypt.AES.sb(b,org.ascrypt.AES.sbox);
	org.ascrypt.AES.sr(b,org.ascrypt.AES.srtab);
	org.ascrypt.AES.ark(b,k.slice(i,i + 16));
	return b;
}
org.ascrypt.AES.id = function(k,ob) {
	var b = ob.slice();
	var l = k.length;
	var i = l - 32;
	org.ascrypt.AES.ark(b,k.slice(l - 16,l));
	org.ascrypt.AES.sr(b,org.ascrypt.AES.isrtab);
	org.ascrypt.AES.sb(b,org.ascrypt.AES.isbox);
	while(i >= 16) {
		org.ascrypt.AES.ark(b,k.slice(i,i + 16));
		org.ascrypt.AES.mci(b);
		org.ascrypt.AES.sr(b,org.ascrypt.AES.isrtab);
		org.ascrypt.AES.sb(b,org.ascrypt.AES.isbox);
		i -= 16;
	}
	org.ascrypt.AES.ark(b,k.slice(0,16));
	return b;
}
org.ascrypt.AES.mc = function(s) {
	var i = 0;
	while(i < 16) {
		var s0 = s[i], s1 = s[i + 1];
		var s2 = s[i + 2], s3 = s[i + 3];
		var h = s0 ^ s1 ^ s2 ^ s3;
		s[i] ^= h ^ org.ascrypt.AES.xtime[s0 ^ s1];
		s[i + 1] ^= h ^ org.ascrypt.AES.xtime[s1 ^ s2];
		s[i + 2] ^= h ^ org.ascrypt.AES.xtime[s2 ^ s3];
		s[i + 3] ^= h ^ org.ascrypt.AES.xtime[s3 ^ s0];
		i += 4;
	}
}
org.ascrypt.AES.mci = function(s) {
	var i = 0;
	while(i < 16) {
		var s0 = s[i], s1 = s[i + 1];
		var s2 = s[i + 2], s3 = s[i + 3];
		var h = s0 ^ s1 ^ s2 ^ s3;
		var xh = org.ascrypt.AES.xtime[h];
		var h1 = org.ascrypt.AES.xtime[org.ascrypt.AES.xtime[xh ^ s0 ^ s2]] ^ h;
		var h2 = org.ascrypt.AES.xtime[org.ascrypt.AES.xtime[xh ^ s1 ^ s3]] ^ h;
		s[i] ^= h1 ^ org.ascrypt.AES.xtime[s0 ^ s1];
		s[i + 1] ^= h2 ^ org.ascrypt.AES.xtime[s1 ^ s2];
		s[i + 2] ^= h1 ^ org.ascrypt.AES.xtime[s2 ^ s3];
		s[i + 3] ^= h2 ^ org.ascrypt.AES.xtime[s3 ^ s0];
		i += 4;
	}
}
org.ascrypt.AES.check = function(k,b) {
	var kl = k.length;
	if(kl != 16 && kl != 24 && kl != 32) throw org.ascrypt.AES.ERROR_KEY;
	if(b.length % 16 != 0) throw org.ascrypt.AES.ERROR_BLOCK;
}
org.ascrypt.ARC4 = function() { }
org.ascrypt.ARC4.__name__ = true;
org.ascrypt.ARC4.encrypt = function(key,bytes,init) {
	if(init == null) init = true;
	org.ascrypt.ARC4.check(key);
	return org.ascrypt.ARC4.core(key,bytes,init);
}
org.ascrypt.ARC4.decrypt = function(key,bytes,init) {
	if(init == null) init = true;
	org.ascrypt.ARC4.check(key);
	return org.ascrypt.ARC4.core(key,bytes,init);
}
org.ascrypt.ARC4.core = function(k,b,n) {
	if(n) org.ascrypt.ARC4.init(k);
	var r = [];
	var l = 0, j = 0;
	var v, t, x;
	var _g1 = 0, _g = b.length;
	while(_g1 < _g) {
		var i = _g1++;
		l = (l + 1) % 256;
		j = (j + org.ascrypt.ARC4.sbox[l]) % 256;
		t = org.ascrypt.ARC4.sbox[l];
		org.ascrypt.ARC4.sbox[l] = org.ascrypt.ARC4.sbox[j];
		org.ascrypt.ARC4.sbox[j] = t;
		x = (org.ascrypt.ARC4.sbox[l] + org.ascrypt.ARC4.sbox[j]) % 256;
		v = org.ascrypt.ARC4.sbox[x];
		r[i] = b[i] ^ v;
	}
	return r;
}
org.ascrypt.ARC4.init = function(k) {
	var l = k.length;
	var t, c = 0;
	var _g = 0;
	while(_g < 256) {
		var i = _g++;
		org.ascrypt.ARC4.mkey[i] = k[i % l];
		org.ascrypt.ARC4.sbox[i] = i;
	}
	var _g = 0;
	while(_g < 256) {
		var j = _g++;
		c = (c + org.ascrypt.ARC4.sbox[j] + org.ascrypt.ARC4.mkey[j]) % 256;
		t = org.ascrypt.ARC4.sbox[j];
		org.ascrypt.ARC4.sbox[j] = org.ascrypt.ARC4.sbox[c];
		org.ascrypt.ARC4.sbox[c] = t;
	}
}
org.ascrypt.ARC4.check = function(k) {
	var kl = k.length;
	if(kl < 5 || kl > 16) throw org.ascrypt.ARC4.ERROR_KEY;
}
org.ascrypt.Base16 = function() { }
org.ascrypt.Base16.__name__ = true;
org.ascrypt.Base16.encode = function(bytes) {
	var l = bytes.length;
	var v, h = [];
	var _g = 0;
	while(_g < l) {
		var i = _g++;
		v = StringTools.hex(bytes[i]).toLowerCase();
		if(v.length < 2) h[i] = "0" + v; else h[i] = v;
	}
	return h.join("");
}
org.ascrypt.Base16.decode = function(text) {
	var i = 0;
	var l = text.length;
	var v, b = [];
	while(i < l) {
		v = HxOverrides.substr(text,i,2);
		b[i / 2 | 0] = Std.parseInt("0x" + v);
		i += 2;
	}
	return b;
}
org.ascrypt.Base64 = function() { }
org.ascrypt.Base64.__name__ = true;
org.ascrypt.Base64.encode = function(bytes) {
	var l = bytes.length;
	var c1 = 0, c2 = 0, c3 = 0;
	var e1 = 0, e2 = 0, e3 = 0, e4 = 0;
	var i = 0, t = "";
	while(i < l) {
		c1 = bytes[i++];
		c2 = bytes[i++];
		c3 = bytes[i++];
		e1 = c1 >> 2;
		e2 = (c1 & 3) << 4 | c2 >> 4;
		e3 = (c2 & 15) << 2 | c3 >> 6;
		e4 = c3 & 63;
		t += org.ascrypt.Base64.chrs.charAt(e1) + org.ascrypt.Base64.chrs.charAt(e2);
		if(i < l) t += org.ascrypt.Base64.chrs.charAt(e3);
		if(i < l) t += org.ascrypt.Base64.chrs.charAt(e4);
	}
	if(Math.isNaN(c2)) t += "=";
	if(Math.isNaN(c3)) t += "=";
	return t;
}
org.ascrypt.Base64.decode = function(text) {
	var l = text.length;
	var c1 = 0, c2 = 0, c3 = 0;
	var e1 = 0, e2 = 0, e3 = 0, e4 = 0;
	var i = 0, b = [];
	while(i < l) {
		e1 = org.ascrypt.Base64.chrs.indexOf(text.charAt(i++));
		e2 = org.ascrypt.Base64.chrs.indexOf(text.charAt(i++));
		e3 = org.ascrypt.Base64.chrs.indexOf(text.charAt(i++));
		e4 = org.ascrypt.Base64.chrs.indexOf(text.charAt(i++));
		c1 = e1 << 2 | e2 >> 4;
		c2 = (e2 & 15) << 4 | e3 >> 2;
		c3 = (e3 & 3) << 6 | e4;
		b.push(c1);
		if(e3 != 64) b.push(c2);
		if(e4 != 64) b.push(c3);
	}
	return b;
}
org.ascrypt.GUID = function() { }
org.ascrypt.GUID.__name__ = true;
org.ascrypt.GUID.create = function() {
	var s, b = [];
	var _g = 0;
	while(_g < 128) {
		var i = _g++;
		b[i] = Math.floor(Math.random() * 128);
	}
	s = org.ascrypt.Base16.encode(org.ascrypt.MD5.compute(b));
	return org.ascrypt.GUID.format(s);
}
org.ascrypt.GUID.format = function(s) {
	var p = [];
	p[0] = HxOverrides.substr(s,0,8);
	p[1] = HxOverrides.substr(s,8,4);
	p[2] = HxOverrides.substr(s,12,4);
	p[3] = HxOverrides.substr(s,16,4);
	p[4] = HxOverrides.substr(s,20,12);
	return p.join("-");
}
org.ascrypt.MD5 = function() { }
org.ascrypt.MD5.__name__ = true;
org.ascrypt.MD5.compute = function(bytes) {
	var b = org.ascrypt.utilities.UTIL.pack(bytes);
	return org.ascrypt.utilities.UTIL.unpack(org.ascrypt.MD5.core(b,bytes.length * 8));
}
org.ascrypt.MD5.computeHMAC = function(key,bytes) {
	return org.ascrypt.utilities.HMAC.compute(key,bytes,org.ascrypt.MD5.compute,64);
}
org.ascrypt.MD5.core = function(x,l) {
	x[l >> 5] |= 128 << l % 32;
	x[(l + 64 >>> 9 << 4) + 14] = l;
	var a = 1732584193, b = -271733879;
	var i = 0, c = -1732584194, d = 271733878;
	while(i < x.length) {
		x[i] |= 0;
		x[i + 1] |= 0;
		x[i + 2] |= 0;
		x[i + 3] |= 0;
		x[i + 4] |= 0;
		x[i + 5] |= 0;
		x[i + 6] |= 0;
		x[i + 7] |= 0;
		x[i + 8] |= 0;
		x[i + 9] |= 0;
		x[i + 10] |= 0;
		x[i + 11] |= 0;
		x[i + 12] |= 0;
		x[i + 13] |= 0;
		x[i + 14] |= 0;
		x[i + 15] |= 0;
		var olda = a, oldb = b;
		var oldc = c, oldd = d;
		a = org.ascrypt.MD5.ff(a,b,c,d,x[i],7,-680876936);
		d = org.ascrypt.MD5.ff(d,a,b,c,x[i + 1],12,-389564586);
		c = org.ascrypt.MD5.ff(c,d,a,b,x[i + 2],17,606105819);
		b = org.ascrypt.MD5.ff(b,c,d,a,x[i + 3],22,-1044525330);
		a = org.ascrypt.MD5.ff(a,b,c,d,x[i + 4],7,-176418897);
		d = org.ascrypt.MD5.ff(d,a,b,c,x[i + 5],12,1200080426);
		c = org.ascrypt.MD5.ff(c,d,a,b,x[i + 6],17,-1473231341);
		b = org.ascrypt.MD5.ff(b,c,d,a,x[i + 7],22,-45705983);
		a = org.ascrypt.MD5.ff(a,b,c,d,x[i + 8],7,1770035416);
		d = org.ascrypt.MD5.ff(d,a,b,c,x[i + 9],12,-1958414417);
		c = org.ascrypt.MD5.ff(c,d,a,b,x[i + 10],17,-42063);
		b = org.ascrypt.MD5.ff(b,c,d,a,x[i + 11],22,-1990404162);
		a = org.ascrypt.MD5.ff(a,b,c,d,x[i + 12],7,1804603682);
		d = org.ascrypt.MD5.ff(d,a,b,c,x[i + 13],12,-40341101);
		c = org.ascrypt.MD5.ff(c,d,a,b,x[i + 14],17,-1502002290);
		b = org.ascrypt.MD5.ff(b,c,d,a,x[i + 15],22,1236535329);
		a = org.ascrypt.MD5.gg(a,b,c,d,x[i + 1],5,-165796510);
		d = org.ascrypt.MD5.gg(d,a,b,c,x[i + 6],9,-1069501632);
		c = org.ascrypt.MD5.gg(c,d,a,b,x[i + 11],14,643717713);
		b = org.ascrypt.MD5.gg(b,c,d,a,x[i],20,-373897302);
		a = org.ascrypt.MD5.gg(a,b,c,d,x[i + 5],5,-701558691);
		d = org.ascrypt.MD5.gg(d,a,b,c,x[i + 10],9,38016083);
		c = org.ascrypt.MD5.gg(c,d,a,b,x[i + 15],14,-660478335);
		b = org.ascrypt.MD5.gg(b,c,d,a,x[i + 4],20,-405537848);
		a = org.ascrypt.MD5.gg(a,b,c,d,x[i + 9],5,568446438);
		d = org.ascrypt.MD5.gg(d,a,b,c,x[i + 14],9,-1019803690);
		c = org.ascrypt.MD5.gg(c,d,a,b,x[i + 3],14,-187363961);
		b = org.ascrypt.MD5.gg(b,c,d,a,x[i + 8],20,1163531501);
		a = org.ascrypt.MD5.gg(a,b,c,d,x[i + 13],5,-1444681467);
		d = org.ascrypt.MD5.gg(d,a,b,c,x[i + 2],9,-51403784);
		c = org.ascrypt.MD5.gg(c,d,a,b,x[i + 7],14,1735328473);
		b = org.ascrypt.MD5.gg(b,c,d,a,x[i + 12],20,-1926607734);
		a = org.ascrypt.MD5.hh(a,b,c,d,x[i + 5],4,-378558);
		d = org.ascrypt.MD5.hh(d,a,b,c,x[i + 8],11,-2022574463);
		c = org.ascrypt.MD5.hh(c,d,a,b,x[i + 11],16,1839030562);
		b = org.ascrypt.MD5.hh(b,c,d,a,x[i + 14],23,-35309556);
		a = org.ascrypt.MD5.hh(a,b,c,d,x[i + 1],4,-1530992060);
		d = org.ascrypt.MD5.hh(d,a,b,c,x[i + 4],11,1272893353);
		c = org.ascrypt.MD5.hh(c,d,a,b,x[i + 7],16,-155497632);
		b = org.ascrypt.MD5.hh(b,c,d,a,x[i + 10],23,-1094730640);
		a = org.ascrypt.MD5.hh(a,b,c,d,x[i + 13],4,681279174);
		d = org.ascrypt.MD5.hh(d,a,b,c,x[i],11,-358537222);
		c = org.ascrypt.MD5.hh(c,d,a,b,x[i + 3],16,-722521979);
		b = org.ascrypt.MD5.hh(b,c,d,a,x[i + 6],23,76029189);
		a = org.ascrypt.MD5.hh(a,b,c,d,x[i + 9],4,-640364487);
		d = org.ascrypt.MD5.hh(d,a,b,c,x[i + 12],11,-421815835);
		c = org.ascrypt.MD5.hh(c,d,a,b,x[i + 15],16,530742520);
		b = org.ascrypt.MD5.hh(b,c,d,a,x[i + 2],23,-995338651);
		a = org.ascrypt.MD5.ii(a,b,c,d,x[i],6,-198630844);
		d = org.ascrypt.MD5.ii(d,a,b,c,x[i + 7],10,1126891415);
		c = org.ascrypt.MD5.ii(c,d,a,b,x[i + 14],15,-1416354905);
		b = org.ascrypt.MD5.ii(b,c,d,a,x[i + 5],21,-57434055);
		a = org.ascrypt.MD5.ii(a,b,c,d,x[i + 12],6,1700485571);
		d = org.ascrypt.MD5.ii(d,a,b,c,x[i + 3],10,-1894986606);
		c = org.ascrypt.MD5.ii(c,d,a,b,x[i + 10],15,-1051523);
		b = org.ascrypt.MD5.ii(b,c,d,a,x[i + 1],21,-2054922799);
		a = org.ascrypt.MD5.ii(a,b,c,d,x[i + 8],6,1873313359);
		d = org.ascrypt.MD5.ii(d,a,b,c,x[i + 15],10,-30611744);
		c = org.ascrypt.MD5.ii(c,d,a,b,x[i + 6],15,-1560198380);
		b = org.ascrypt.MD5.ii(b,c,d,a,x[i + 13],21,1309151649);
		a = org.ascrypt.MD5.ii(a,b,c,d,x[i + 4],6,-145523070);
		d = org.ascrypt.MD5.ii(d,a,b,c,x[i + 11],10,-1120210379);
		c = org.ascrypt.MD5.ii(c,d,a,b,x[i + 2],15,718787259);
		b = org.ascrypt.MD5.ii(b,c,d,a,x[i + 9],21,-343485551);
		a += olda;
		b += oldb;
		c += oldc;
		d += oldd;
		i += 16;
	}
	return [a,b,c,d];
}
org.ascrypt.MD5.cmn = function(q,a,b,x,s,t) {
	return org.ascrypt.MD5.rol(a + q + x + t,s) + b;
}
org.ascrypt.MD5.ff = function(a,b,c,d,x,s,t) {
	return org.ascrypt.MD5.cmn(b & c | ~b & d,a,b,x,s,t);
}
org.ascrypt.MD5.gg = function(a,b,c,d,x,s,t) {
	return org.ascrypt.MD5.cmn(b & d | c & ~d,a,b,x,s,t);
}
org.ascrypt.MD5.hh = function(a,b,c,d,x,s,t) {
	return org.ascrypt.MD5.cmn(b ^ c ^ d,a,b,x,s,t);
}
org.ascrypt.MD5.ii = function(a,b,c,d,x,s,t) {
	return org.ascrypt.MD5.cmn(c ^ (b | ~d),a,b,x,s,t);
}
org.ascrypt.MD5.rol = function(n,c) {
	return n << c | n >>> 32 - c;
}
org.ascrypt.RMD160 = function() { }
org.ascrypt.RMD160.__name__ = true;
org.ascrypt.RMD160.compute = function(bytes) {
	var b = org.ascrypt.utilities.UTIL.pack(bytes);
	return org.ascrypt.utilities.UTIL.unpack(org.ascrypt.RMD160.core(b,bytes.length * 8));
}
org.ascrypt.RMD160.computeHMAC = function(key,bytes) {
	return org.ascrypt.utilities.HMAC.compute(key,bytes,org.ascrypt.RMD160.compute,64);
}
org.ascrypt.RMD160.core = function(x,l) {
	x[l >> 5] |= 128 << l % 32;
	x[(l + 64 >>> 9 << 4) + 14] = l;
	var i = 0, h0 = 1732584193, h1 = -271733879;
	var h2 = -1732584194, h3 = 271733878, h4 = -1009589776;
	while(i < x.length) {
		var t, a1 = h0, b1 = h1, c1 = h2;
		var d1 = h3, e1 = h4, a2 = h0, b2 = h1;
		var c2 = h2, d2 = h3, e2 = h4;
		var _g = 0;
		while(_g < 80) {
			var j = _g++;
			t = org.ascrypt.RMD160.add(a1,org.ascrypt.RMD160.f(j,b1,c1,d1));
			t = org.ascrypt.RMD160.add(t,x[i + org.ascrypt.RMD160.r1[j]]);
			t = org.ascrypt.RMD160.add(t,org.ascrypt.RMD160.k1(j));
			t = org.ascrypt.RMD160.add(org.ascrypt.RMD160.rol(t,org.ascrypt.RMD160.s1[j]),e1);
			a1 = e1;
			e1 = d1;
			d1 = org.ascrypt.RMD160.rol(c1,10);
			c1 = b1;
			b1 = t;
			t = org.ascrypt.RMD160.add(a2,org.ascrypt.RMD160.f(79 - j,b2,c2,d2));
			t = org.ascrypt.RMD160.add(t,x[i + org.ascrypt.RMD160.r2[j]]);
			t = org.ascrypt.RMD160.add(t,org.ascrypt.RMD160.k2(j));
			t = org.ascrypt.RMD160.add(org.ascrypt.RMD160.rol(t,org.ascrypt.RMD160.s2[j]),e2);
			a2 = e2;
			e2 = d2;
			d2 = org.ascrypt.RMD160.rol(c2,10);
			c2 = b2;
			b2 = t;
		}
		t = org.ascrypt.RMD160.add(h1,org.ascrypt.RMD160.add(c1,d2));
		h1 = org.ascrypt.RMD160.add(h2,org.ascrypt.RMD160.add(d1,e2));
		h2 = org.ascrypt.RMD160.add(h3,org.ascrypt.RMD160.add(e1,a2));
		h3 = org.ascrypt.RMD160.add(h4,org.ascrypt.RMD160.add(a1,b2));
		h4 = org.ascrypt.RMD160.add(h0,org.ascrypt.RMD160.add(b1,c2));
		h0 = t;
		i += 16;
	}
	return [h0,h1,h2,h3,h4];
}
org.ascrypt.RMD160.f = function(j,x,y,z) {
	return 0 <= j && j <= 15?x ^ y ^ z:16 <= j && j <= 31?x & y | ~x & z:32 <= j && j <= 47?(x | ~y) ^ z:48 <= j && j <= 63?x & z | y & ~z:64 <= j && j <= 79?x ^ (y | ~z):Math.NEGATIVE_INFINITY | 0;
}
org.ascrypt.RMD160.k1 = function(j) {
	return 0 <= j && j <= 15?0:16 <= j && j <= 31?1518500249:32 <= j && j <= 47?1859775393:48 <= j && j <= 63?-1894007588:64 <= j && j <= 79?-1454113458:Math.NEGATIVE_INFINITY | 0;
}
org.ascrypt.RMD160.k2 = function(j) {
	return 0 <= j && j <= 15?1352829926:16 <= j && j <= 31?1548603684:32 <= j && j <= 47?1836072691:48 <= j && j <= 63?2053994217:64 <= j && j <= 79?0:Math.NEGATIVE_INFINITY | 0;
}
org.ascrypt.RMD160.add = function(x,y) {
	var l = (x & 65535) + (y & 65535);
	var m = (x >> 16) + (y >> 16) + (l >> 16);
	return m << 16 | l & 65535;
}
org.ascrypt.RMD160.rol = function(n,c) {
	return n << c | n >>> 32 - c;
}
org.ascrypt.ROT13 = function() { }
org.ascrypt.ROT13.__name__ = true;
org.ascrypt.ROT13.encode = function(bytes) {
	return org.ascrypt.ROT13.core(bytes);
}
org.ascrypt.ROT13.decode = function(bytes) {
	return org.ascrypt.ROT13.core(bytes);
}
org.ascrypt.ROT13.core = function(b) {
	var c, r = [];
	var p, l = b.length;
	var _g = 0;
	while(_g < l) {
		var i = _g++;
		c = String.fromCharCode(b[i]);
		p = org.ascrypt.ROT13.chrs.indexOf(c);
		if(p > -1) r[i] = HxOverrides.cca(org.ascrypt.ROT13.chrs,p + 13); else r[i] = b[i];
	}
	return r;
}
org.ascrypt.SHA1 = function() { }
org.ascrypt.SHA1.__name__ = true;
org.ascrypt.SHA1.compute = function(bytes) {
	var b = org.ascrypt.utilities.UTIL.pack(bytes,false);
	return org.ascrypt.utilities.UTIL.unpack(org.ascrypt.SHA1.core(b,bytes.length * 8),false);
}
org.ascrypt.SHA1.computeHMAC = function(key,bytes) {
	return org.ascrypt.utilities.HMAC.compute(key,bytes,org.ascrypt.SHA1.compute,64);
}
org.ascrypt.SHA1.core = function(x,l) {
	x[l >> 5] |= 128 << 24 - l % 32;
	x[(l + 64 >> 9 << 4) + 15] = l;
	var i = 0, w = [], a = 1732584193;
	var b = -271733879, c = -1732584194;
	var d = 271733878, e = -1009589776;
	var i1 = 0;
	while(i1 < x.length) {
		var olda = a, oldb = b;
		var oldc = c, oldd = d, olde = e;
		var _g = 0;
		while(_g < 80) {
			var j = _g++;
			if(j < 16) w[j] = x[i1 + j]; else w[j] = org.ascrypt.SHA1.rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16],1);
			var t = org.ascrypt.SHA1.add(org.ascrypt.SHA1.add(org.ascrypt.SHA1.rol(a,5),org.ascrypt.SHA1.ft(j,b,c,d)),org.ascrypt.SHA1.add(org.ascrypt.SHA1.add(e,w[j]),org.ascrypt.SHA1.kt(j)));
			e = d;
			d = c;
			c = org.ascrypt.SHA1.rol(b,30);
			b = a;
			a = t;
		}
		a = org.ascrypt.SHA1.add(a,olda);
		b = org.ascrypt.SHA1.add(b,oldb);
		c = org.ascrypt.SHA1.add(c,oldc);
		d = org.ascrypt.SHA1.add(d,oldd);
		e = org.ascrypt.SHA1.add(e,olde);
		i1 += 16;
	}
	return [a,b,c,d,e];
}
org.ascrypt.SHA1.kt = function(t) {
	return t < 20?1518500249:t < 40?1859775393:t < 60?-1894007588:-899497514;
}
org.ascrypt.SHA1.ft = function(t,b,c,d) {
	if(t < 20) return b & c | ~b & d;
	if(t < 40) return b ^ c ^ d;
	if(t < 60) return b & c | b & d | c & d;
	return b ^ c ^ d;
}
org.ascrypt.SHA1.rol = function(n,c) {
	return n << c | n >>> 32 - c;
}
org.ascrypt.SHA1.add = function(one,two) {
	var l = (one & 65535) + (two & 65535);
	var m = (one >> 16) + (two >> 16) + (l >> 16);
	return m << 16 | l & 65535;
}
org.ascrypt.SHA256 = function() { }
org.ascrypt.SHA256.__name__ = true;
org.ascrypt.SHA256.compute = function(bytes) {
	var b = org.ascrypt.utilities.UTIL.pack(bytes,false);
	return org.ascrypt.utilities.UTIL.unpack(org.ascrypt.SHA256.core(b,bytes.length * 8),false);
}
org.ascrypt.SHA256.computeHMAC = function(key,bytes) {
	return org.ascrypt.utilities.HMAC.compute(key,bytes,org.ascrypt.SHA256.compute,64);
}
org.ascrypt.SHA256.core = function(m,l) {
	var a, b, c, d;
	var e, f, g, h, i = 0;
	var t1, t2, w = new Array();
	var k = [1116352408,1899447441,-1245643825,-373957723,961987163,1508970993,-1841331548,-1424204075,-670586216,310598401,607225278,1426881987,1925078388,-2132889090,-1680079193,-1046744716,-459576895,-272742522,264347078,604807628,770255983,1249150122,1555081692,1996064986,-1740746414,-1473132947,-1341970488,-1084653625,-958395405,-710438585,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,-2117940946,-1838011259,-1564481375,-1474664885,-1035236496,-949202525,-778901479,-694614492,-200395387,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,-2067236844,-1933114872,-1866530822,-1538233109,-1090935817,-965641998];
	var r = [1779033703,-1150833019,1013904242,-1521486534,1359893119,-1694144372,528734635,1541459225];
	m[l >> 5] |= 128 << 24 - l % 32;
	m[(l + 64 >> 9 << 4) + 15] = l;
	while(i < m.length) {
		a = r[0];
		b = r[1];
		c = r[2];
		d = r[3];
		e = r[4];
		f = r[5];
		g = r[6];
		h = r[7];
		var _g = 0;
		while(_g < 64) {
			var j = _g++;
			if(j < 16) w[j] = m[j + i]; else w[j] = org.ascrypt.SHA256.add(org.ascrypt.SHA256.add(org.ascrypt.SHA256.add(org.ascrypt.SHA256.g1256(w[j - 2]),w[j - 7]),org.ascrypt.SHA256.g0256(w[j - 15])),w[j - 16]);
			t1 = org.ascrypt.SHA256.add(org.ascrypt.SHA256.add(org.ascrypt.SHA256.add(org.ascrypt.SHA256.add(h,org.ascrypt.SHA256.s1256(e)),org.ascrypt.SHA256.ch(e,f,g)),k[j]),w[j]);
			t2 = org.ascrypt.SHA256.add(org.ascrypt.SHA256.s0256(a),org.ascrypt.SHA256.maj(a,b,c));
			h = g;
			g = f;
			f = e;
			e = org.ascrypt.SHA256.add(d,t1);
			d = c;
			c = b;
			b = a;
			a = org.ascrypt.SHA256.add(t1,t2);
		}
		r[0] = org.ascrypt.SHA256.add(a,r[0]);
		r[1] = org.ascrypt.SHA256.add(b,r[1]);
		r[2] = org.ascrypt.SHA256.add(c,r[2]);
		r[3] = org.ascrypt.SHA256.add(d,r[3]);
		r[4] = org.ascrypt.SHA256.add(e,r[4]);
		r[5] = org.ascrypt.SHA256.add(f,r[5]);
		r[6] = org.ascrypt.SHA256.add(g,r[6]);
		r[7] = org.ascrypt.SHA256.add(h,r[7]);
		i += 16;
	}
	return r;
}
org.ascrypt.SHA256.s = function(x,n) {
	return x >>> n | x << 32 - n;
}
org.ascrypt.SHA256.ch = function(x,y,z) {
	return x & y ^ ~x & z;
}
org.ascrypt.SHA256.maj = function(x,y,z) {
	return x & y ^ x & z ^ y & z;
}
org.ascrypt.SHA256.s0256 = function(x) {
	return org.ascrypt.SHA256.s(x,2) ^ org.ascrypt.SHA256.s(x,13) ^ org.ascrypt.SHA256.s(x,22);
}
org.ascrypt.SHA256.s1256 = function(x) {
	return org.ascrypt.SHA256.s(x,6) ^ org.ascrypt.SHA256.s(x,11) ^ org.ascrypt.SHA256.s(x,25);
}
org.ascrypt.SHA256.g0256 = function(x) {
	return org.ascrypt.SHA256.s(x,7) ^ org.ascrypt.SHA256.s(x,18) ^ x >>> 3;
}
org.ascrypt.SHA256.g1256 = function(x) {
	return org.ascrypt.SHA256.s(x,17) ^ org.ascrypt.SHA256.s(x,19) ^ x >>> 10;
}
org.ascrypt.SHA256.add = function(one,two) {
	var l = (one & 65535) + (two & 65535);
	var m = (one >> 16) + (two >> 16) + (l >> 16);
	return m << 16 | l & 65535;
}
org.ascrypt.XXTEA = function() { }
org.ascrypt.XXTEA.__name__ = true;
org.ascrypt.XXTEA.encrypt = function(key,bytes) {
	org.ascrypt.XXTEA.check(key,bytes);
	var h = org.ascrypt.utilities.UTIL.pack(key);
	var v = org.ascrypt.utilities.UTIL.pack(bytes);
	if(v.length <= 1) v[1] = 0;
	var n = v.length;
	var z = v[n - 1], y = v[0], d = -1640531527;
	var m, e, s = 0, q = Math.floor(6 + 52 / n);
	while(q-- > 0) {
		s += d;
		e = s >>> 2 & 3;
		var _g = 0;
		while(_g < n) {
			var i = _g++;
			y = v[(i + 1) % n];
			m = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (s ^ y) + (h[i & 3 ^ e] ^ z);
			z = v[i] += m;
		}
	}
	return org.ascrypt.utilities.UTIL.unpack(v);
}
org.ascrypt.XXTEA.decrypt = function(key,bytes) {
	org.ascrypt.XXTEA.check(key,bytes);
	var h = org.ascrypt.utilities.UTIL.pack(key);
	var v = org.ascrypt.utilities.UTIL.pack(bytes);
	var n = v.length, z = v[n - 1], y = v[0], d = -1640531527;
	var m, e, q = Math.floor(6 + 52 / n), s = q * d;
	while(s != 0) {
		e = s >>> 2 & 3;
		var i = n - 1;
		while(i >= 0) {
			z = v[i > 0?i - 1:n - 1];
			m = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (s ^ y) + (h[i & 3 ^ e] ^ z);
			y = v[i] -= m;
			i--;
		}
		s -= d;
	}
	return org.ascrypt.utilities.UTIL.unpack(v);
}
org.ascrypt.XXTEA.check = function(k,b) {
	if(k.length != 16) throw org.ascrypt.XXTEA.ERROR_KEY;
	if(b.length < 8 || b.length % 4 != 0) throw org.ascrypt.XXTEA.ERROR_BLOCK;
}
org.ascrypt.common = {}
org.ascrypt.common.OperationMode = function() { }
org.ascrypt.common.OperationMode.__name__ = true;
org.ascrypt.encoding = {}
org.ascrypt.encoding.BigEndian = function() { }
org.ascrypt.encoding.BigEndian.__name__ = true;
org.ascrypt.encoding.BigEndian.textToBytes = function(text) {
	var b = [];
	var i = 0, l = text.length * 2;
	while(i < l) {
		b[i] = HxOverrides.cca(text,i / 2 | 0) >>> 8 & 255;
		b[i + 1] = HxOverrides.cca(text,i / 2 | 0) & 255;
		i += 2;
	}
	return b;
}
org.ascrypt.encoding.BigEndian.bytesToText = function(bytes) {
	var l = bytes.length;
	var c, i = 0, s = "";
	while(i < l) {
		c = bytes[i] << 8 | bytes[i + 1] & 255;
		s += String.fromCharCode(c);
		i += 2;
	}
	return s;
}
org.ascrypt.encoding.LittleEndian = function() { }
org.ascrypt.encoding.LittleEndian.__name__ = true;
org.ascrypt.encoding.LittleEndian.textToBytes = function(text) {
	var b = [];
	var i = 0, l = text.length * 2;
	while(i < l) {
		b[i] = HxOverrides.cca(text,i / 2 | 0) & 255;
		b[i + 1] = HxOverrides.cca(text,i / 2 | 0) >>> 8 & 255;
		i += 2;
	}
	return b;
}
org.ascrypt.encoding.LittleEndian.bytesToText = function(bytes) {
	var l = bytes.length;
	var c, i = 0, s = "";
	while(i < l) {
		c = bytes[i] & 255 | bytes[i + 1] << 8;
		s += String.fromCharCode(c);
		i += 2;
	}
	return s;
}
org.ascrypt.encoding.UTF8 = function() { }
org.ascrypt.encoding.UTF8.__name__ = true;
org.ascrypt.encoding.UTF8.textToBytes = function(text) {
	var l = text.length;
	var c, p = 0, b = [];
	var _g = 0;
	while(_g < l) {
		var i = _g++;
		c = HxOverrides.cca(text,i);
		if(c <= 127) {
			b[p] = c;
			p++;
		} else if(c <= 2047) {
			b[p] = c >>> 6 | 192;
			b[p + 1] = c & 63 | 128;
			p += 2;
		} else if(c <= 65535) {
			b[p] = c >>> 12 | 224;
			b[p + 1] = c >>> 6 & 63 | 128;
			b[p + 2] = c & 63 | 128;
			p += 3;
		} else if(c <= 1114111) {
			b[p] = c >>> 18 | 240;
			b[p + 1] = c >>> 12 & 63 | 128;
			b[p + 2] = c >>> 6 & 63 | 128;
			b[p + 3] = c & 63 | 128;
			p += 4;
		}
	}
	return b;
}
org.ascrypt.encoding.UTF8.bytesToText = function(bytes) {
	var i = 0;
	var l = bytes.length;
	var c, s = "";
	while(i < l) {
		c = 0;
		if((bytes[i] & 128) != 128) c = bytes[i]; else if((bytes[i] & 240) == 240) {
			c |= (bytes[i] & 7) << 18;
			c |= (bytes[i + 1] & 63) << 12;
			c |= (bytes[i + 2] & 63) << 6;
			c |= bytes[i + 3] & 63;
			i += 3;
		} else if((bytes[i] & 224) == 224) {
			c |= (bytes[i] & 15) << 12;
			c |= (bytes[i + 1] & 63) << 6;
			c |= bytes[i + 2] & 63;
			i += 2;
		} else if((bytes[i] & 192) == 192) {
			c |= (bytes[i] & 31) << 6;
			c |= bytes[i + 1] & 63;
			i++;
		}
		s += String.fromCharCode(c);
		i++;
	}
	return s;
}
org.ascrypt.padding = {}
org.ascrypt.padding.PKCS7 = function() { }
org.ascrypt.padding.PKCS7.__name__ = true;
org.ascrypt.padding.PKCS7.pad = function(bytes,size) {
	var c = bytes.slice();
	var s = size - c.length % size;
	var _g = 0;
	while(_g < s) {
		var i = _g++;
		c[c.length] = s;
	}
	return c;
}
org.ascrypt.padding.PKCS7.unpad = function(bytes) {
	var c = bytes.slice();
	var v, s = c[c.length - 1];
	var _g = 0;
	while(_g < s) {
		var i = _g++;
		v = c[c.length - 1];
		c.pop();
		if(s != v) throw org.ascrypt.utilities.UTIL.format(org.ascrypt.padding.PKCS7.ERROR_VALUE,[Std.string(v),Std.string(s)]);
	}
	return c;
}
org.ascrypt.padding.ZEROS = function() { }
org.ascrypt.padding.ZEROS.__name__ = true;
org.ascrypt.padding.ZEROS.pad = function(bytes,size) {
	var c = bytes.slice();
	while(c.length % size != 0) c[c.length] = 0;
	return c;
}
org.ascrypt.padding.ZEROS.unpad = function(bytes) {
	var c = bytes.slice();
	while(c[c.length - 1] == 0) c.pop();
	return c;
}
org.ascrypt.utilities = {}
org.ascrypt.utilities.CBC = function() { }
org.ascrypt.utilities.CBC.__name__ = true;
org.ascrypt.utilities.CBC.encrypt = function(key,bytes,size,encrypt,iv) {
	var r = [];
	var l = bytes.length;
	var i = 0;
	while(i < l) {
		var _g = 0;
		while(_g < size) {
			var j = _g++;
			bytes[i + j] ^= iv[j];
		}
		r = r.concat(encrypt(key,bytes.slice(i,i + size)));
		iv = r.slice(i,i + size);
		i += size;
	}
	return r;
}
org.ascrypt.utilities.CBC.decrypt = function(key,bytes,size,decrypt,iv) {
	var l = bytes.length;
	var t, r = [];
	var i = 0;
	while(i < l) {
		t = bytes.slice(i,i + size);
		r = r.concat(decrypt(key,t));
		var _g = 0;
		while(_g < size) {
			var j = _g++;
			r[i + j] ^= iv[j];
		}
		iv = t.slice(0,size);
		i += size;
	}
	return r;
}
org.ascrypt.utilities.CTR = function() { }
org.ascrypt.utilities.CTR.__name__ = true;
org.ascrypt.utilities.CTR.encrypt = function(key,bytes,size,encrypt,iv) {
	return org.ascrypt.utilities.CTR.core(key,bytes,size,encrypt,iv);
}
org.ascrypt.utilities.CTR.decrypt = function(key,bytes,size,encrypt,iv) {
	return org.ascrypt.utilities.CTR.core(key,bytes,size,encrypt,iv);
}
org.ascrypt.utilities.CTR.core = function(k,b,s,c,v) {
	var bl = b.length;
	var e = [], x = v.slice();
	var i = 0;
	while(i < bl) {
		e = c(k,x);
		var _g = 0;
		while(_g < s) {
			var j = _g++;
			b[i + j] ^= e[j];
		}
		var l = s - 1;
		while(l >= 0) {
			--l;
			x[l]++;
			if(x[l] != 0) break;
		}
		i += s;
	}
	return b;
}
org.ascrypt.utilities.ECB = function() { }
org.ascrypt.utilities.ECB.__name__ = true;
org.ascrypt.utilities.ECB.encrypt = function(key,bytes,size,encrypt) {
	return org.ascrypt.utilities.ECB.core(key,bytes,size,encrypt);
}
org.ascrypt.utilities.ECB.decrypt = function(key,bytes,size,decrypt) {
	return org.ascrypt.utilities.ECB.core(key,bytes,size,decrypt);
}
org.ascrypt.utilities.ECB.core = function(k,b,s,c) {
	var r = [];
	var l = b.length;
	var i = 0;
	while(i < l) {
		r = r.concat(c(k,b.slice(i,i + s)));
		i += s;
	}
	return r;
}
org.ascrypt.utilities.HMAC = function() { }
org.ascrypt.utilities.HMAC.__name__ = true;
org.ascrypt.utilities.HMAC.compute = function(key,bytes,hash,size) {
	var hk = key.slice();
	var ik = [], ok = [];
	if(key.length > size) hk = hash(key);
	while(hk.length < size) hk[hk.length] = 0;
	var hkl = hk.length;
	var _g = 0;
	while(_g < hkl) {
		var i = _g++;
		ik[i] = hk[i] ^ 54;
		ok[i] = hk[i] ^ 92;
	}
	ik = ik.concat(bytes);
	ok = ok.concat(hash(ik));
	return hash(ok);
}
org.ascrypt.utilities.UTIL = function() { }
org.ascrypt.utilities.UTIL.__name__ = true;
org.ascrypt.utilities.UTIL.pack = function(bytes,little) {
	if(little == null) little = true;
	var w = [];
	var l = bytes.length;
	var b1 = 0, b2 = 0, b3 = 0, b4 = 0, i = 0;
	while(i < l) {
		if(little) {
			b1 = bytes[i];
			b2 = bytes[i + 1] << 8;
			b3 = bytes[i + 2] << 16;
			b4 = bytes[i + 3] << 24;
		} else {
			b1 = bytes[i] << 24;
			b2 = bytes[i + 1] << 16;
			b3 = bytes[i + 2] << 8;
			b4 = bytes[i + 3];
		}
		w[i / 4 | 0] = b1 | b2 | b3 | b4;
		i += 4;
	}
	return w;
}
org.ascrypt.utilities.UTIL.unpack = function(words,little) {
	if(little == null) little = true;
	var b = [];
	var l = words.length;
	var b1, b2, b3, b4;
	var _g = 0;
	while(_g < l) {
		var i = _g++;
		if(little) {
			b1 = words[i] & 255;
			b2 = (words[i] & 65280) >> 8;
			b3 = (words[i] & 16711680) >> 16;
			b4 = (words[i] & -16777216) >> 24;
			if(b4 < 0) b4 += 256;
		} else {
			b1 = (words[i] & -16777216) >> 24;
			b2 = (words[i] & 16711680) >> 16;
			b3 = (words[i] & 65280) >> 8;
			b4 = words[i] & 255;
			if(b1 < 0) b1 += 256;
		}
		b[i * 4] = b1;
		b[i * 4 + 1] = b2;
		b[i * 4 + 2] = b3;
		b[i * 4 + 3] = b4;
	}
	return b;
}
org.ascrypt.utilities.UTIL.format = function(string,args) {
	var l = args.length;
	var _g = 0;
	while(_g < l) {
		var i = _g++;
		var parts = string.split("{" + i + "}");
		string = parts.join(args[i]);
	}
	return string;
}
Math.__name__ = ["Math"];
Math.NaN = Number.NaN;
Math.NEGATIVE_INFINITY = Number.NEGATIVE_INFINITY;
Math.POSITIVE_INFINITY = Number.POSITIVE_INFINITY;
Math.isFinite = function(i) {
	return isFinite(i);
};
Math.isNaN = function(i) {
	return isNaN(i);
};
String.__name__ = true;
Array.__name__ = true;
Date.__name__ = ["Date"];
org.ascrypt.AES.ERROR_KEY = "Invalid key size. Key size needs to be either 128, 192 or 256 bits.\n";
org.ascrypt.AES.ERROR_MODE = "Invalid mode of operation. Supported modes are ECB, CBC, CTR or NONE.\n";
org.ascrypt.AES.ERROR_BLOCK = "Invalid block size. Block size is fixed at 128 bits.\n";
org.ascrypt.AES.srtab = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11];
org.ascrypt.AES.sbox = [99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
org.ascrypt.ARC4.sbox = [];
org.ascrypt.ARC4.mkey = [];
org.ascrypt.ARC4.ERROR_KEY = "Invalid key size. Key size needs to be 40 - 128 bits.\n";
org.ascrypt.Base64.chrs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
org.ascrypt.RMD160.r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
org.ascrypt.RMD160.r2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
org.ascrypt.RMD160.s1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
org.ascrypt.RMD160.s2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
org.ascrypt.ROT13.chrs = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMabcdefghijklmnopqrstuvwxyzabcdefghijklm";
org.ascrypt.XXTEA.ERROR_KEY = "Invalid key size. Key size is fixed at 128 bits.\n";
org.ascrypt.XXTEA.ERROR_BLOCK = "Invalid block size. Minimum block size is 64 bits and the block size needs to be multiple of 32 bits.\n";
org.ascrypt.common.OperationMode.ECB = "ecb";
org.ascrypt.common.OperationMode.CBC = "cbc";
org.ascrypt.common.OperationMode.CTR = "ctr";
org.ascrypt.common.OperationMode.NONE = "none";
org.ascrypt.padding.PKCS7.ERROR_VALUE = "Invalid padding value. Got {0}, expected {1}.";
Main.main();
})();
