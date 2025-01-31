package cz.cloudfield.cloud.crypto.key;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/keys/")
public class KeyManagementController {

    private final KeyManager keyManager;

    public KeyManagementController(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void createKey(@RequestBody CreateKeyRequestDTO request) {
        keyManager.createKey(request.keyAlias(), request.keyVersion(), request.keyAlgorithm(), request.keyType(), request.keyData());
    }

    @GetMapping
    public List<CryptographicKey> listKeys() {
        return keyManager.listKeys();
    }
}
