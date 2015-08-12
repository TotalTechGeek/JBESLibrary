import java.io.FileInputStream;
import java.io.IOException;
import beslibrary.encryption.BasylHashAlgorithms;
import beslibrary.encryption.BasylKeyGenerator;
import beslibrary.encryption.FileMutatedBKG;
import beslibrary.encryption.IBasylKeyGenerator;
import beslibrary.rsa.BasylRSAUtilities;



public class Main {

	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException, Exception 
	{
		// TODO Auto-generated method stub
		//BasylKeyGenerator bkg = new BasylKeyGenerator("Hello World. I am Jesse Mitchell. This is a test for Fynite.", BasylKeyGenerator.INITIAL/4, BasylKeyGenerator.ROUNDS*2, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, "ABCD", new byte[32], new byte[4], new byte[4], true, null);
		//System.out.println(new BasylRSAUtilities().GeneratePrivateKeyPEM(CreateGeneratorFromPassword(args[0]), Short.parseShort(args[1])));
		
		
		IBasylKeyGenerator bkg = new FileMutatedBKG(new BasylKeyGenerator("BasylKeyGenerationFromFile", BasylKeyGenerator.INITIAL /4 , BasylKeyGenerator.ROUNDS, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, BasylKeyGenerator.ADDITIONALKEY, new byte[32], new byte[4], new byte[4], true, null), new FileInputStream(args[0]));
		System.out.println(new BasylRSAUtilities().GeneratePrivateKeyPEM(bkg, Short.parseShort(args[1])));
	}    
	
	private static int Unsigned(byte x)
    {
     	return x & 0xFF;
    }
     
	
	 private static BasylKeyGenerator CreateGeneratorFromPassword(String pass)
     {
         byte[] hashOfPassword = BasylHashAlgorithms.BasylHashUno(pass, "BasylEncryptionStandard_" + pass, pass.length() * 2 + 5, 256 * 256 + pass.length() * 2, 700, 100, "BasylRSA_ECC_" + pass);

         char[] charHash = new char[hashOfPassword.length];
         
         
         byte[] randomizerA = new byte[4];
         byte[] randomizerB = new byte[4];

         int posA = Unsigned(hashOfPassword[0]) * Unsigned(hashOfPassword[3]) + Unsigned(hashOfPassword[2]) * Unsigned(hashOfPassword[1]);
         int posB = Unsigned(hashOfPassword[1]) * Unsigned(hashOfPassword[0]) + Unsigned(hashOfPassword[3]) * Unsigned(hashOfPassword[2]);

         if (posA == posB) posA += Unsigned(hashOfPassword[4]);
         for (int i = 0; i < hashOfPassword.length; i++)
         {
             charHash[i] = (char)(hashOfPassword[i] & 0xFF);
             randomizerA[posA++ % 4] ^= hashOfPassword[posA % hashOfPassword.length];
             randomizerB[posB++ % 4] ^= hashOfPassword[posB % hashOfPassword.length];
         }
         
         
         return new BasylKeyGenerator(new String(charHash) + pass, BasylKeyGenerator.INITIAL /4 , BasylKeyGenerator.ROUNDS, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, BasylKeyGenerator.ADDITIONALKEY, hashOfPassword, randomizerA, randomizerB, true, null);
     }

}
