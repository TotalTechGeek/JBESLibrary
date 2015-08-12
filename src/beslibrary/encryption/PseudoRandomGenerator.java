package beslibrary.encryption;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;


public class PseudoRandomGenerator {

	private ArrayList<Long> Generation;
    private int rounds;
    private int position;
    private String recycleKey;
    private byte[] seedKey;
    private byte[] SHASeedKey;

    private BasylPseudoAdaptor basylPseudoAdaptor;

    private boolean stopRecycle = false;
    private int leftoff;
    
    private static int Unsigned(byte x)
    {
    	return x & 0xFF;
    }

    public PseudoRandomGenerator() 
    {
    	 this(1024*16); //16 KB.
    }

    public PseudoRandomGenerator(int size) 
    {
    	this(size, "");
       
    }

    public PseudoRandomGenerator(int size, String key)
    {
    	 this(size, key, 1105);
    }

    public PseudoRandomGenerator(int size, String key, int rounds) 
    {
    	this(size, key, rounds, new BasylPseudoAdaptor());
        
    }

    public PseudoRandomGenerator(int size, String key, int rounds, BasylPseudoAdaptor basylPseudoAdaptor)
    {
        position = 0;
        this.rounds = rounds;
        Generation = new ArrayList<Long>();
        this.recycleKey = "";
        ResizeBoth(size);
        this.basylPseudoAdaptor = basylPseudoAdaptor;
        Generate(key);
    }


    /// <summary>
    /// Resizes the list for generating.
    /// </summary>
    /// <param name="size"></param>
    private void ResizeGeneration(int size)
    {
        while(Generation.size() < size)
        {
            Generation.add(0l);
        }

    }

    /// <summary>
    /// Resizes both lists at the same time.
    /// </summary>
    /// <param name="size"></param>
    private void ResizeBoth(int size)
    {
        //ResizeGenerated(size);
        ResizeGeneration(size);
    }

    /// <summary>
    /// Stops the recycling of the values.
    /// </summary>
    public void StopRecycling()
    {
        stopRecycle = true;
    }

    /// <summary>
    /// Sets whether there is recycling or not.
    /// </summary>
    /// <param name="n"></param>
    public void SetRecycling(boolean n)
    {
        this.stopRecycle = !n;
    }





    /// <summary>
    /// Sets the SHA seed to enhance encryption.
    /// </summary>
    /// <param name="sha"></param>
    public void SetSHA(byte[] sha)
    {
        this.SHASeedKey = sha;
    }

    /// <summary>
    /// Sets the extra seed to enhance encryption.
    /// </summary>
    /// <param name="key"></param>
    public void SetSeedKey(byte[] key)
    {
        this.seedKey = key;
    }


    /// <summary>
    /// Sets a string as a seed to enhance encryption
    /// </summary>
    /// <param name="r"></param>
    public void SetRecycleKey(String r)
    {
        this.recycleKey = r;
    }


    /** 
    * Sets how many of the bytes generated are left out. Enhances unpredictability.
    * 
    * @param left
    **/ 
    public void SetLeftoff(int left)
    {
        this.leftoff = left;
    }

    /// <summary>
    /// Expands the key.
    /// </summary>
    /// <param name="times"></param>
    public void ExpandKey(int times)
    {
        if (times == 0) return; //This is a bug fix that I can no longer remove without compatibility issues );
        ArrayList<Long> expander = new ArrayList<Long>();


        for(long k = (0); k < times; k++)
        {
        	Generation.set(0, Generation.get(0) + times);
        	Generation.set(2, Generation.get(2) + k);
        	Generation.set(3, Generation.get(3) + times + k + expander.size());
        	Generation.set(4, Generation.get(4) + Generation.size());
        	
            if (k % 2 == 0)
                Cipher();
            else
                CipherB();

            
            expander.addAll(Generation);

        }

        Generation = expander;
    }
   

    /// <summary>
    /// Generate the Random Data using the key.
    /// </summary>
    /// <param name="key"></param>
    private void Generate(String key)
    {
        Long seed = Long.valueOf(1);
        char[] keyN = key.toCharArray();
        Generation.set(0, Long.valueOf(Generation.size()));

        int pos = 0;
        //Seed the array with the password, and also make the seed.
        for (char let : keyN)
        {
            //Generation[pos++ + 1] += let;
            
        	Generation.set(pos + 1, Generation.get(pos + 1) + let);
        	pos++;
        	seed += let;
        }
        
        //Seed the data with generated values from a seed function.
        for(int i = 0; i < Generation.size(); i++)
        {
            //Generation[(int)i] += (SeedFunction(i, seed));
        
        	Generation.set(i, Generation.get(i) + SeedFunction((long)i, seed));
        }

        //Cipher it.
        for(int i = 0; i < rounds; i++)
        {
            basylPseudoAdaptor.Shuffle(Generation, i);
            if (i % 2 == 0)
                Cipher();
            else
                CipherB();
        }

  
    }

    /// <summary>
    /// This method will mutate the data again for a new fresh start.
    /// </summary>
    public void Recycle()
    {
        Recycle(false);
    }

    /// <summary>
    /// This method will mutate the data again for a new fresh start.
    /// </summary>
    private void Recycle(boolean enhanced)
    {
       
        if (enhanced)
        {
            Cipher(position);
        }
        else
        {
            //Add the recycle key to the Generation Scheme.
            for (int i = 0; i < recycleKey.length(); i++)
            {

                //Generation[i] += recycleKey[i];
            
            	Generation.set(i, Generation.get(i) + recycleKey.charAt(i));
            }

            //Add the SHA to the Generation Scheme
            if (SHASeedKey != null)
            {
                for (int i = 0; i < SHASeedKey.length; i++)
                {

                    //Generation[i] += SHASeedKey[i];
                	Generation.set(i, Generation.get(i) + Unsigned(SHASeedKey[i]));
                }

            }

            //add the seed key to the generation scheme.
            if (seedKey != null)
            {
                for (int i = 0; i < seedKey.length; i++)
                {
                    //Generation[i] += seedKey[i];
                	Generation.set(i, Generation.get(i) + Unsigned(seedKey[i]));
                }
            }
        }

        

        for (int i = 0;i < 1;i++) //could be adjusted
        {
            if (!(enhanced && i == 0))
            {
                Cipher();
            }
            CipherB();
        }

        basylPseudoAdaptor.Recycle(Generation);
        position = 0;
    }
    
    /// <summary>
    /// This method adds previous numbers in the array, and it gets moduloed and mutated
    /// through waterfalling. The process is not reversible, and generates high entropy.
    /// </summary>
    private void Cipher()
    {
        Cipher(1);
    }

    /// <summary>
    /// This method adds previous numbers in the array, and it gets moduloed and mutated
    /// through waterfalling. The process is not reversible, and generates high entropy.
    /// </summary>
    private void Cipher(int start)
    {
        for (int i = start; i < Generation.size(); i++)
        {
             Generation.set(i, Generation.get(i) + Generation.get(i-1));
             //if(Generation.get(i) < 0) System.out.println("Oh");
             if (Generation.get(i) > 400000000) Generation.set(i, Generation.get(i) % 913131);
        }
    }

    /// <summary>
    /// Same here. It just does it in reverse.
    /// </summary>
    private void CipherB()
    {
        for (int i = Generation.size() - 2; i >= 0; i--)
        {
        	Generation.set(i, Generation.get(i) + Generation.get(i+1));
            if (Generation.get(i) > 400000000) Generation.set(i, Generation.get(i) % 913131);
        }
    }

    /// <summary>
    /// Returns a random byte from the next position.
    /// </summary>
    /// <returns></returns>
    public byte GetRandomByte()
    {
        if ((position + leftoff) >= Generation.size())
        {
            if(stopRecycle)
            {
                position = 0;
            }
            else
            Recycle(true);
        }

        byte r = (byte)(Generation.get(position) % 256);
        Generation.set(position, Generation.get(position) + Unsigned(r));

        if (position != 0)
        {
            Generation.set(position, Generation.get(position) + Generation.get(position-1));
            if (Generation.get(position) > 400000000) Generation.set(position, Generation.get(position) % 913131);
        }

        if(SHASeedKey != null && position < SHASeedKey.length)
        {
            Generation.set(position, Generation.get(position) + Unsigned(SHASeedKey[position]));
        }

        if(seedKey != null && position < seedKey.length)
        {
            Generation.set(position, Generation.get(position) + Unsigned(seedKey[position]));
        }

        if(position < recycleKey.length())
        {
            Generation.set(position, Generation.get(position) + recycleKey.charAt(position));
        }
        

        position++;
        return r;
    }

    /// <summary>
    /// Returns a random 4 byte integer.
    /// </summary>
    /// <returns></returns>
    public int GetRandomInt()
    {
    	byte[] arr = new byte[] { GetRandomByte(), GetRandomByte(), GetRandomByte(), GetRandomByte() };
    	ByteBuffer w = ByteBuffer.wrap(arr);
    	return w.getInt();
    }


    /// <summary>
    /// Fills the array with random bytes.
    /// </summary>
    /// <param name="arr"></param>
    public void FillBytes(byte[] arr)
    {
        for(int i = 0; i < arr.length; i++)
        {
            arr[i] = GetRandomByte();
        }
    }

    /// <summary>
    /// Drops all the values.
    /// </summary>
    public void Drop()
    {
        Generation.clear();
    }

    /// <summary>
    /// This seeds the generation array.
    /// </summary>
    /// <param name="pos"></param>
    /// <param name="seed"></param>
    /// <returns></returns>
    private Long SeedFunction(Long pos, Long seed)
    {
    	long r = basylPseudoAdaptor.SeedFunction(pos, seed);
        return r;
    }
	
	
}
