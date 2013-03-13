import org.ascrypt.*;
import org.ascrypt.encoding.*;
import org.ascrypt.utilities.*;

/**
* Creates GUID's using MD5 hash for random bytes.
* <br/><br/>GUID is a special identifier used to provide a reference number which is unique in any context.
* @author Mika Palmu
*/
class org.ascrypt.GUID
{
	/**
	* Creates a new GUID using MD5 hash for random bytes.
	* @return The generated GUID string.
	*/
	public static function create():String
	{
		var s:String, b:Array = [];
		for (var j:Number = 0; j < 128; j++)
		{
			b[j] = Math.floor(Math.random() * 128);
		}
		s = Base16.encode(MD5.compute(b));
		return format(s);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function format(s:String):String
	{
		var p:Array = [];
		p[0] = s.substr(0, 8);
		p[1] = s.substr(8, 4);
		p[2] = s.substr(12, 4);
		p[3] = s.substr(16, 4);
		p[4] = s.substr(20, 12);
		return p.join("-");
	}
	
}
