package cn.learndevops.filecrypto;

import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class CryptoUtil {
    public static byte[] kdf_scrypt(char[] password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        var fact = SecretKeyFactory.getInstance("SCRYPT","BC");
        String salt_str = "ce05d8d3693061482deae2c11cdef8ce696f90f66958fc51dbbd3561ad8e9587";
        byte[] saltBytes = Hex.decode(salt_str);
        return fact.generateSecret(
                new ScryptKeySpec(password,saltBytes,
                        4096,8,6,256))
                .getEncoded();
    }
}
