package chatapplication_server.components.base;

import javax.crypto.spec.IvParameterSpec;
import java.util.ArrayList;
import java.util.List;

public class Constants {
    //Diffie-Hellman constants
    public static final long G = 101;
    public static final long Q = 4906;
    public static final long P = 977;
    //AES constants
    public static String ALGORITHM = "AES/CBC/PKCS5Padding";
    public static String KEY_ALGORITHM = "AES";
    public static IvParameterSpec INITIALIZATION_VECTOR = new IvParameterSpec(new byte[]{1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0});
}
