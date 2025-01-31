package cz.cloudfield.cloud.crypto.key;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;

@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public interface CryptographicKey {

    String getKeyAlias();

    String getKeyAlgorithm();

    String getKeyVersion();

    String getKeyType();

    LocalDateTime getCreated();

    LocalDateTime getUpdated();
}
