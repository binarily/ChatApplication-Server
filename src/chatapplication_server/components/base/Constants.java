package chatapplication_server.components.base;

import javax.crypto.spec.IvParameterSpec;
import java.util.Dictionary;
import java.util.HashMap;

public class Constants {
    public static final double G = 2;
    public static final double Q = 1024;
    public static final double P = 3;
    public static String ALGORITHM = "AES/CBC/PKCS5Padding";
    public static String KEY_ALGORITHM = "AES";
    public static byte[] KEY = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    public static IvParameterSpec INITIALIZATION_VECTOR = new IvParameterSpec(new byte[]{1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0});
    public static HashMap<String, byte[]> CLIENT_KEYS = new HashMap<>();

    static {
        CLIENT_KEYS.put("Thanassis", new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        CLIENT_KEYS.put("Hi", new byte[]{31,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        CLIENT_KEYS.put("Not Thanassis", new byte[]{31,1,2,3,4,5,6,7,8,9,10,11,11,13,14,15});
    }

}
