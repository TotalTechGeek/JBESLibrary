package beslibrary.rsa;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.w3c.dom.*;


/**
 * Converts a private or public RSA key from the XML Security format (used also
 * in .NET) to the RSA key format in PEM format. 
 *
 * The output key is written on standard output.
 *
 * In case of private key, the output format is the "traditional" format of the 
 * key, i.e. NOT the newer PKCS#8 format. The output keys are unencrypted. To
 * convert to PKCS#8 and/or encrypt the private key, use openssl with the
 * -topk8 option: 
 *    openssl pkcs8 -topk8 -in privkey_rsa.pem -out privkey.pem
 * 
 * Created by matous.borak@platanus.cz, 2008.
 * See http://www.platanus.cz/blog/xml_key_to_pem_en.html
 *
 * Heavily inspired by the PvkConvert utility made by Michel Gallant, see
 *   http://www.jensign.com/JavaScience/PvkConvert/. Thanks for it!
 *
 */
public class XMLToPEMConverter {

  private static final int PRIVATE_KEY = 1;
  private static final int PUBLIC_KEY = 2;
  private static final String[] PRIVATE_KEY_XML_NODES =  { "Modulus", "Exponent", "P", "Q", "DP", "DQ", "InverseQ", "D" };
  private static final String[] PUBLIC_KEY_XML_NODES =  { "Modulus", "Exponent" };

  public static String Convert(String data) {

	
    try {

      Document XMLSecKeyDoc = parseXMLFile(data);
      //System.out.print("Determining the key type: ");
      int keyType = getKeyType(XMLSecKeyDoc);
      if (keyType == PRIVATE_KEY || keyType == PUBLIC_KEY) {
        //System.out.println("seems to be a " + ( keyType == PRIVATE_KEY ? "private" : "public" ) + " XML Security key");
      } else {
        System.exit(1);
      }

      //System.out.print("Checking the XML file structure: ");
      if (checkXMLRSAKey(keyType, XMLSecKeyDoc)) {
        //System.out.println("OK");
      } else {
        System.exit(1);
      }

      String pem = "";
      //System.out.println("Outputting the resulting key:\n");
      if (keyType == PRIVATE_KEY) 
      {
        
    	  
    	pem = convertXMLRSAPrivateKeyToPEM(XMLSecKeyDoc);
        
    	String result = "";
    	result +=  ("-----BEGIN PRIVATE KEY-----\n");
        
        result += (splitUp(pem,64)) + "\n";   
        
        result += ("-----END PRIVATE KEY-----");
        return result;
      } else 
      {
        pem = convertXMLRSAPublicKeyToPEM(XMLSecKeyDoc);
        String result = "";
        result += ("-----BEGIN PUBLIC KEY-----\n");
        result += (splitUp(pem, 64)) + "\n";
        result += ("-----END PUBLIC KEY-----");
        return result;
      }

    }

    catch (Exception e) {
      System.err.println(e);
    }
    return "";
  }
  
  private static String splitUp(String x, int len)
  {
	  String result = "";
	  while(x.length() >= len)
	  {
		  result += x.substring(0, len) + '\n';
		  x = x.substring(len);
	  }
	  if(x.length() != 0) result += x;
	  return result;
  }

  private static int getKeyType(Document xmldoc) {

    Node root = xmldoc.getFirstChild();
    if (!root.getNodeName().equals("RSAKeyValue")) {
      //System.out.println("Expecting <RSAKeyValue> node, encountered <" + root.getNodeName() + ">");
      return 0;
    }
    NodeList children = root.getChildNodes();
    if (children.getLength() == PUBLIC_KEY_XML_NODES.length) {
      return PUBLIC_KEY;
    } 
    return PRIVATE_KEY;

  }

  private static boolean checkXMLRSAKey(int keyType, Document xmldoc) {

    Node root = xmldoc.getFirstChild();
    NodeList children = root.getChildNodes();
    String[] wantedNodes = {};
    if (keyType == PRIVATE_KEY) {
      wantedNodes = PRIVATE_KEY_XML_NODES;
    } else {
      wantedNodes = PUBLIC_KEY_XML_NODES;
    }
    for (int j = 0; j < wantedNodes.length; j++) {
      String wantedNode = wantedNodes[j];
      boolean found = false;
      for (int i = 0; i < children.getLength(); i++) {
        if (children.item(i).getNodeName().equals(wantedNode)) {
          found = true;
          break;
        }
      }
      if (!found) {
        //System.out.println("Cannot find node <" + wantedNode + ">");
        return false;
      }
    }
    return true;

  }

  private static String convertXMLRSAPrivateKeyToPEM(Document xmldoc) {

    Node root = xmldoc.getFirstChild();
    NodeList children = root.getChildNodes();

    BigInteger modulus = null, exponent = null, primeP = null, primeQ = null, 
               primeExponentP = null, primeExponentQ = null, 
               crtCoefficient = null, privateExponent = null;

    for (int i = 0; i < children.getLength(); i++) {

      Node node = children.item(i);
      String textValue = node.getTextContent();
      if (node.getNodeName().equals("Modulus")) {
        modulus = new BigInteger(b64decode(textValue));
       
      } else if (node.getNodeName().equals("Exponent")) {
        exponent = new BigInteger(b64decode(textValue));
      } else if (node.getNodeName().equals("P")) {
        primeP = new BigInteger(b64decode(textValue));
        //System.out.println(primeP);
      } else if (node.getNodeName().equals("Q")) {
        primeQ = new BigInteger(b64decode(textValue));
      } else if (node.getNodeName().equals("DP")) {
        primeExponentP = new BigInteger(b64decode(textValue));
      } else if (node.getNodeName().equals("DQ")) {
        primeExponentQ = new BigInteger(b64decode(textValue));
      } else if (node.getNodeName().equals("InverseQ")) {
        crtCoefficient = new BigInteger(b64decode(textValue));
      } else if (node.getNodeName().equals("D")) {
        privateExponent = new BigInteger(b64decode(textValue));
      }

    }

    try {

      RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec (
        modulus, exponent, privateExponent, primeP, primeQ, 
        primeExponentP, primeExponentQ, crtCoefficient);

      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PrivateKey key = keyFactory.generatePrivate(keySpec);
      return b64encode(key.getEncoded());

    } catch (Exception e) {
      //System.out.println(e);
    }
    return null;

  }

  private static String convertXMLRSAPublicKeyToPEM(Document xmldoc) {

    Node root = xmldoc.getFirstChild();
    NodeList children = root.getChildNodes();

    BigInteger modulus = null, exponent = null;

    for (int i = 0; i < children.getLength(); i++) {

      Node node = children.item(i);
      String textValue = node.getTextContent();
      if (node.getNodeName().equals("Modulus")) {
        modulus = new BigInteger(b64decode(textValue));
      } else if (node.getNodeName().equals("Exponent")) {
        exponent = new BigInteger(b64decode(textValue));
      }

    }

    try {

      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);

      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PublicKey key = keyFactory.generatePublic(keySpec);
      return b64encode(key.getEncoded());

    } catch (Exception e) {
      //System.out.println(e);
    }
    return null;

  }

  private static Document parseXMLFile(String resource) {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      InputSource is = new InputSource(new StringReader(resource));
      Document document = builder.parse(is);
      return document;
    } catch(Exception e) {
      System.err.println(e); 
      return null;
    } 	
  }

  private static final String b64encode(byte[] data) {
    /*BASE64Encoder enc = new sun.misc.BASE64Encoder() ;
    String b64str = enc.encodeBuffer(data).trim();
    return b64str;*/
	  return new String(Base64.getEncoder().encode(data)).trim();
  }

  private static final byte[] b64decode(String data) {
    byte[] bytes = Base64.getDecoder().decode(data.trim());
      return bytes;
  }


}
