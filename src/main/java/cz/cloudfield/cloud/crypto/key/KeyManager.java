package cz.cloudfield.cloud.crypto.key;

import javax.crypto.SecretKey;
import java.util.List;

public interface KeyManager {

    SecretKey getKey(String alias, String keyVersion);

    void createKey(String alias, String keyVersion, String keyAlgorithm, String keyType, byte[] keyData);

    List<CryptographicKey> listKeys();
}
