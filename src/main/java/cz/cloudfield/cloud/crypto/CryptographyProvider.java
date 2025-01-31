package cz.cloudfield.cloud.crypto;

public interface CryptographyProvider {

    byte[] encrypt(String algorithm, byte[] plaintext, String keyAlias);

    byte[] decrypt(String algorithm, byte[] ciphertext, String keyAlias);

    byte[] sign(String algorithm, byte[] data, String keyAlias);

    boolean verify(String algorithm, byte[] data, byte[] signature, String keyAlias);
}
