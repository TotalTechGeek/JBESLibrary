package beslibrary.rsa;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;


public class XMLExport 
{

	private static String b64encode(BigInteger z)
	{
		return new String(Base64.getEncoder().encode(z.toByteArray()));
	}
	
	public static String XMLExport(BigInteger e, BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger d, BigInteger inverseQ)
	{
		String result = "";
		result += "<RSAKeyValue>\n";
		result +=   "<Modulus>" + b64encode(p.multiply(q)) + "</Modulus>\n";
		result +=   "<Exponent>" + b64encode(e) +  "</Exponent>\n";
		result +=   "<P>"+ b64encode(p) + "</P>\n";
		result +=   "<Q>" + b64encode(q) + "</Q>\n";
		result +=   "<DP>" + b64encode(dp) + "</DP>\n";
		result +=   "<DQ>" + b64encode(dq) + "</DQ>\n";
		result +=   "<InverseQ>" + b64encode(inverseQ) + "</InverseQ>\n";
		result +=   "<D>" + b64encode(d) + "</D>\n";
		result += "</RSAKeyValue>";
		
		
		return result;
	}
	
	
	
}
