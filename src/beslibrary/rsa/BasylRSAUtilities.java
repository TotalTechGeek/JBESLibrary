package beslibrary.rsa;

import java.math.BigInteger;

import beslibrary.encryption.IBasylKeyGenerator;

public class BasylRSAUtilities implements Runnable
{

	
	private BigInteger p, q;
	private IBasylKeyGenerator kg;
	private int size;
	public String GeneratePrivateKeyPEM(IBasylKeyGenerator kg, int nearSize) throws InterruptedException
	{
		return XMLToPEMConverter.Convert(GeneratePrivateKeyXML(kg, nearSize));
	}
	
	public String GeneratePrivateKeyXML(IBasylKeyGenerator kg, int nearSize) throws InterruptedException
	{
		this.size = nearSize;
		this.kg = kg;
		Thread thread = new Thread(this);
		thread.run();
		q = FindLargePrime(kg, size/2 + 8);
		thread.join();
		
		BigInteger gcd, ONE = BigInteger.valueOf(1);
        
		if (p.compareTo(q) < 0)
        {
            gcd = p;
            p = q;
            q = gcd;
        }
		
        BigInteger e = BigInteger.valueOf(65537);
        BigInteger pSub1 = p.subtract(ONE);
        BigInteger qSub1 = q.subtract(ONE);
        gcd = pSub1.gcd(qSub1);
        BigInteger lcm = pSub1.divide(gcd).multiply(qSub1);
        BigInteger d = e.modInverse(lcm);
        		
		
        BigInteger dP, dQ, qInv;

        dP = d.remainder(pSub1);
        dQ = d.remainder(qSub1);
        qInv = q.modInverse(p);

		return (XMLExport.XMLExport(e, p, q, dP, dQ, d, qInv));
	}

	@Override
	public void run() 
	{
		// TODO Auto-generated method stub
		p = FindLargePrime(kg, size/2 + 8);
	}
	
	private BigInteger FindLargePrime(IBasylKeyGenerator gen, int size)
	{
		  //fills an array with random bytes. This is used for the prime search.
        byte[] vals = new byte[(int)Math.ceil(size / 8.0f)];

        synchronized (gen)
        {
            for (int i = 0; i < 20; i++)
            {
                gen.FillBytes(vals);
            }

            for (int k = 0; k < 2; k++)
                for (int i = 0; i < vals.length; i++)
                {
                    for (int n = 0; n < 3; n++)
                        gen.GetRandomByte();
                    
                    vals[i] = gen.EncryptByte(vals[i]);
                }
        }
        
        for (int i = 0; i < vals.length / 2; i++) 
        { 
        	byte temp = vals[i]; // swap numbers 
        	vals[i] = vals[vals.length - 1 - i]; 
        	vals[vals.length - 1 - i] = temp; 
        	
        }
        
        


        //searches for the prime number, decreases until it finds one that tests to be prime. 
        BigInteger gco = new BigInteger(vals);
        if(gco.compareTo(BigInteger.valueOf(0)) < 0)
        {
            gco = gco.multiply( BigInteger.valueOf( -1));
        }

        BigInteger TWO = BigInteger.valueOf(2);
        if (gco.mod(TWO).equals(BigInteger.valueOf(0)))
        {
            gco = gco.subtract(BigInteger.valueOf(1));
        }
       
  
        while (!gco.isProbablePrime(1))
        {
            gco = gco.subtract(TWO);
           
        }
       
        
        return gco;
      
	}
	
	
}
