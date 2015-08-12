package beslibrary.encryption;

public class BasylHashAlgorithms 
{

	/**
	 * This is the first Basyl Hash algorithm that was designed. 
	 * 
	 * @param str
	 * @param pass
	 * @param hashSize
	 * @param keySize
	 * @param rounds
	 * @param skipOver
	 * @param additionalPass
	 * @return
	 */
	public static byte[] BasylHashUno(String str, String pass, int hashSize, int keySize, int rounds, int skipOver, String additionalPass)
    {
        PseudoRandomGenerator prng = new PseudoRandomGenerator(keySize, pass, rounds);
        prng.SetRecycleKey(additionalPass);

        
        IBasylKeyGenerator wk = new BasylWeakKeyGenerator(prng);
        BESCipher cipher = new BESCipher(wk);
        
        
        prng.Recycle();

        char[] zed = str.toCharArray();
        for(char n : zed)
        {
            byte q = (byte)n;
            q = cipher.EncryptLeft(q);
        }


        for (int i = 0; i < skipOver; i++)
        {
            for (int x = 0; x < 4; x++ )
                prng.GetRandomByte();
        }

        int max = (prng.GetRandomByte() & 0xFF) * (prng.GetRandomByte() & 0xFF) + (prng.GetRandomByte() & 0xFF);
       //System.out.println(max);
        for (int i = 0; i < max; i++)
        {
            for (int x = 0; x < 4; x++)
                prng.GetRandomByte();
        }

        byte[] BHU = new byte[hashSize];
        wk.FillBytes(BHU, 0, BHU.length);

        for (int i = 0; i < hashSize; i++)
        {
            BHU[i] ^= prng.GetRandomByte();
            cipher.EncryptRight(BHU);
        }

        
        
        return BHU;
    }
	
}
