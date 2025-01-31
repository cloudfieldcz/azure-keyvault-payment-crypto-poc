package cz.cloudfield.cloud.crypto;

import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "spring.cloud.azure.keyvault.enabled", havingValue = "true")
public class KeyVaultCryptographyProvider implements CryptographyProvider {

    private final KeyClient keyClient;

    public KeyVaultCryptographyProvider(KeyClient keyClient) {
        this.keyClient = keyClient;
    }

    @Override
    public byte[] encrypt(String algorithm, byte[] plaintext, String keyAlias) {
        EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.fromString(algorithm);
        CryptographyClient cryptoClient = keyClient.getCryptographyClient(keyAlias);
        return cryptoClient.encrypt(encryptionAlgorithm, plaintext).getCipherText();
    }

    @Override
    public byte[] decrypt(String algorithm, byte[] ciphertext, String keyAlias) {
        EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.fromString(algorithm);
        CryptographyClient cryptoClient = keyClient.getCryptographyClient(keyAlias);
        return cryptoClient.decrypt(encryptionAlgorithm, ciphertext).getPlainText();
    }

    @Override
    public byte[] sign(String algorithm, byte[] data, String keyAlias) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm);
        CryptographyClient cryptoClient = keyClient.getCryptographyClient(keyAlias);
        return cryptoClient.signData(signatureAlgorithm, data).getSignature();
    }

    @Override
    public boolean verify(String algorithm, byte[] data, byte[] signature, String keyAlias) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm);
        CryptographyClient cryptoClient = keyClient.getCryptographyClient(keyAlias);
        return cryptoClient.verifyData(signatureAlgorithm, data, signature).isValid();
    }
}
