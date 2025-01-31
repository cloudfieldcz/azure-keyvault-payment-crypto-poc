package cz.cloudfield.cloud.crypto.key;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CryptographicKeyRepository extends JpaRepository<CryptographicKeyEntity, Long> {

    Optional<CryptographicKeyEntity> findByKeyAliasAndKeyVersion(String keyAlias, String keyVersion);

    @Query("from CryptographicKeyEntity")
    List<CryptographicKey> findAllKeys();
}
