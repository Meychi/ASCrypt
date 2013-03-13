/**
* Encodes and decodes bytes with ROT13 algorithm.
* <br/><br/>ROT13 is a simple variation of the Caesar cipher, developed in ancient Rome.
* @author Mika Palmu
*/
class org.ascrypt.ROT13 
{
	/**
	* Characters used in the ROT13 calculation.
	*/
	private static var chrs:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMabcdefghijklmnopqrstuvwxyzabcdefghijklm";
	
	/**
	* Encodes bytes with ROT13 algorithm.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @return An array of encoded bytes.
	*/
	public static function encode(bytes:Array):Array
	{
		return core(bytes);
	}
	
	/**
	* Decodes bytes with ROT13 algorithm.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @return An array of decoded bytes.
	*/
	public static function decode(bytes:Array):Array
	{
		return core(bytes);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function core(b:Array):Array
	{
		var l:Number = b.length;
		var c:String, p:Number, r:Array = [];
		for (var i:Number = 0; i < l; i++)
		{
			c = String.fromCharCode(b[i]);
			p = chrs.indexOf(c); // Position in chrs
			if (p > -1) r[i] = chrs.charCodeAt(p + 13);
			else r[i] = b[i];
		}
		return r;
	}
	
}
