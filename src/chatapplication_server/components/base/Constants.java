package chatapplication_server.components.base;

import javax.crypto.spec.IvParameterSpec;
import java.util.ArrayList;
import java.util.List;

public class Constants {
    public static final long G = 101;
    public static final long Q = 4906;
    public static final long P = 977;
    public static String ALGORITHM = "AES/CBC/PKCS5Padding";
    public static String KEY_ALGORITHM = "AES";
    public static IvParameterSpec INITIALIZATION_VECTOR = new IvParameterSpec(new byte[]{1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0});
    public static List<byte[]> CLIENT_KEYS = new ArrayList<>();

    //TODO: change to a list of keys (no ID-based)
    static {
        CLIENT_KEYS.add(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        CLIENT_KEYS.add(new byte[]{31,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        CLIENT_KEYS.add(new byte[]{31,1,2,3,4,5,6,7,8,9,10,11,11,13,14,15});
    }

}
