package cz.cloudfield.cloud.crypto.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;

public class CryptoUtils {
    private static final Logger logger = LoggerFactory.getLogger(CryptoUtils.class);

    public static final String SECURITY_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    static {
        if (Security.getProvider(SECURITY_PROVIDER) == null) {
            logger.info("Registring security provider {}.", SECURITY_PROVIDER);
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static byte[] encrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/ECB/NoPadding", SECURITY_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data);
    }

    public static byte[] decrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/ECB/NoPadding", SECURITY_PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(data);
    }

    public static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static byte[] leftPaddToMultipleOf(int base, byte[] array, byte paddingByte) {
        if (array.length == 0) {
            byte[] result = new byte[base];
            Arrays.fill(result, paddingByte);
            return result;
        } else {
            int diff = array.length % base;
            if (diff == 0) {
                return array;
            } else {
                byte[] result = new byte[array.length + (base - diff)];
                System.arraycopy(array, 0, result, result.length - array.length, array.length);
                Arrays.fill(result, 0, result.length - array.length, paddingByte);
                return result;
            }
        }
    }

    /**
     * <p>
     * Pad the transaction data according to ISO/IEC 7816-4 (which is equivalent
     * to method 2 of ISO/IEC 9797-1); hence add a mandatory <code>'80'</code> byte to the
     * right of transaction data, and then add the smallest number of <code>'00'</code> bytes
     * to the right such that the length of resulting message is a multiple of 8 bytes.
     * </p>
     *
     * @param data - transaction data
     *
     * @return padded transaction data
     */
    public static String addIsoPadding(String data) {
        return addIsoPadding(data, 8);
    }

    /**
     * <p>
     * Pad the transaction data according to ISO/IEC 7816-4 (which is equivalent
     * to method 2 of ISO/IEC 9797-1); hence add a mandatory <code>'80'</code> byte to the
     * right of transaction data, and then add the smallest number of <code>'00'</code> bytes
     * to the right such that the length of resulting message is a multiple of n bytes.
     * </p>
     *
     * @param data - transaction data
     * @param n    - multiple of bytes
     *
     * @return padded transaction data
     */
    public static String addIsoPadding(String data, int n) {
        StringBuilder trxDataPadded = new StringBuilder(data);
        int remainder = trxDataPadded.length() % (n * 2);

        if (remainder % 2 != 0) {
            throw new IllegalArgumentException("Data are HEX encoded array of bytes and cannot be of odd length.");
        }

        if (remainder >= 2) {
            trxDataPadded.append("80");
            remainder += 2;

            for (int i = 0; i < (n * 2) - remainder; i += 2) {
                trxDataPadded.append("00");
            }
        }
        return trxDataPadded.toString();
    }
}
