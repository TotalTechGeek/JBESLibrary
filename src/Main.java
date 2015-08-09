import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import beslibrary.encryption.BESCipher;
import beslibrary.encryption.BasylInputStream;
import beslibrary.encryption.BasylKeyGenerator;
import beslibrary.encryption.BasylOutputStream;
import beslibrary.encryption.PseudoRandomGenerator;


public class Main {

	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		
		FileInputStream fs = new FileInputStream("Hello.bes");
		BasylInputStream bos = new BasylInputStream(fs, BasylInputStream.ReadFromStream(fs, "HelloWo", BasylKeyGenerator.INITIAL, BasylKeyGenerator.ROUNDS, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, BasylKeyGenerator.ADDITIONALKEY, null));
		
		byte[] z = new byte[] {0, 0, 0, 0};
		
		bos.read(z);
		
		for(int i = 0; i < z.length; i++)
		{
			System.out.println(z[i]);
		}
		
		bos.close();
		
		
	}

}
