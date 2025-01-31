package cz.cloudfield.cloud.crypto.key;

import cz.cloudfield.cloud.crypto.CryptographyProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;
import java.util.List;

@Component
public class DatabaseKeyManager implements KeyManager {

    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final CryptographyProvider cryptographyProvider;

    private final String masterKeyAlias;

    public DatabaseKeyManager(
        CryptographicKeyRepository cryptographicKeyRepository,
        CryptographyProvider cryptographyProvider,
        @Value("${master-key-alias}") String masterKeyAlias) {
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.cryptographyProvider = cryptographyProvider;
        this.masterKeyAlias = masterKeyAlias;
    }

    @Override
    public SecretKey getKey(String alias, String keyVersion) {
        CryptographicKeyEntity key = cryptographicKeyRepository.findByKeyAliasAndKeyVersion(alias, keyVersion)
            .orElseThrow(() -> new IllegalArgumentException("Key not found: " + alias));

        byte[] keyBytes = cryptographyProvider.decrypt("RSA-OAEP-256", HexFormat.of().parseHex(key.getKeyData()), masterKeyAlias);

        return new SecretKeySpec(keyBytes, key.getKeyAlgorithm());
    }

    @Override
    public void createKey(String alias, String keyVersion, String keyAlgorithm, String keyType, byte[] keyData) {
        byte[] encryptedKeyData = cryptographyProvider.encrypt("RSA-OAEP-256", keyData, masterKeyAlias);

        CryptographicKeyEntity key = new CryptographicKeyEntity();
        key.setKeyAlias(alias);
        key.setKeyData(HexFormat.of().withUpperCase().formatHex(encryptedKeyData));
        key.setKeyAlgorithm(keyAlgorithm);
        key.setKeyType(keyType);
        key.setKeyVersion(keyVersion);

        cryptographicKeyRepository.save(key);
    }

    @Override
    public List<CryptographicKey> listKeys() {
        return cryptographicKeyRepository.findAllKeys();
    }
}
