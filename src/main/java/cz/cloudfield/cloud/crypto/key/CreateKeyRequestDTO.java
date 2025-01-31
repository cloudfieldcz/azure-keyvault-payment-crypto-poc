package cz.cloudfield.cloud.crypto.key;

public record CreateKeyRequestDTO(
        String keyAlias,
        byte[] keyData,
        String keyAlgorithm,
        String keyVersion,
        String keyType
) {
}
