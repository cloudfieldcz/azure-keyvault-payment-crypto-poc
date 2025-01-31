package cz.cloudfield.cloud.crypto.payment.key;

import cz.cloudfield.cloud.crypto.key.CryptographicKey;
import cz.cloudfield.cloud.crypto.key.KeyManager;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Primary
public class HardcodedKeyManager implements KeyManager {

    private static final Map<String, SecretKey> KEY_MAP = new ConcurrentHashMap<>(Map.of(
        "pvk-tdes", new SecretKeySpec(HexFormat.of().parseHex("0123456789ABCDEFFEDCBA98765432100123456789ABCDEF"), "DESede"),
        "zpk-tdes", new SecretKeySpec(HexFormat.of().parseHex("0123456789ABCDEFFEDCBA98765432100123456789ABCDEF"), "DESede"),
        "kek-aes", new SecretKeySpec(HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"), "AES")
    ));

    @Override
    public SecretKey getKey(String alias, String keyVersion) {
        if (!KEY_MAP.containsKey(alias)) {
            throw new IllegalArgumentException("Key not found: " + alias);
        }

        return KEY_MAP.get(alias);
    }

    @Override
    public void createKey(String alias, String keyVersion, String keyAlgorithm, String keyType, byte[] keyData) {
        KEY_MAP.putIfAbsent(alias, new SecretKeySpec(keyData, keyAlgorithm));
    }

    @Override
    public List<CryptographicKey> listKeys() {
//        return KEY_MAP.entrySet().stream()
//            .map(entry -> new CryptographicKeyDTO(entry.getKey(), entry.getValue().getAlgorithm(), null, null, null, null))
//            .toList();
        return null;
    }
}
