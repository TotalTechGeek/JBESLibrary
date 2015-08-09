package beslibrary.encryption;

import java.util.ArrayList;

public class StrongerBasylPseudoAdaptor extends BasylPseudoAdaptor 
{
	
	  /// <summary>
    /// Returns a position to swap.
    /// </summary>
    /// <param name="current"></param>
    /// <param name="depth"></param>
    /// <returns></returns>
    private int Layers(ArrayList<Long> x, long current, long depth)
    {
        if (depth <= 0)
        {
            return (int)(current % (long)x.size());   
        }

        return Layers(x, x.get((int)(current % (long)x.size())), depth - 1);
    }



    public void Shuffle(ArrayList<Long> x, int round)
    {

        if (round % 100 == 2)
        {
            for (int i = 0; i < x.size(); i++)
            {
                Long temporary = x.get(i);
                int otherPosition = Layers(x, x.get(i), ( ((temporary << 2) ^ (temporary >> 2)) % 8 + 1));
                OddSwap(x, i, otherPosition);
            }

        }
    }

}
