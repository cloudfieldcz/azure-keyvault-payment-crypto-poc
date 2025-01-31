package cz.cloudfield.cloud.crypto.payment;

import cz.cloudfield.cloud.crypto.key.KeyManager;
import cz.cloudfield.cloud.crypto.utils.CryptoUtils;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

@Component
public class PinBlockConstructor {

    private final KeyManager keyManager;

    public PinBlockConstructor(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public String constructPinBlock(String pin, String pan) throws GeneralSecurityException {
        // Convert the PIN Field and PAN Field to byte arrays
        byte[] pinField = preparePINField(pin);
        byte[] panField = preparePANField(pan);

        // XOR the PIN Field and PAN Field to get the PIN Block
        byte[] pinBlock = new byte[8];
        for (int i = 0; i < 8; i++) {
            pinBlock[i] = (byte) (pinField[i] ^ panField[i]);
        }

        SecretKey zpk = keyManager.getKey("zpk-tdes", "01");

        // Encrypt the PIN Block
        byte[] encryptedPinBlock = CryptoUtils.encrypt(zpk, pinBlock);

        // Convert to hexadecimal string
        return HexFormat.of().withUpperCase().formatHex(encryptedPinBlock);
    }

    private byte[] preparePINField(String pin) {
        StringBuilder pinFieldBuilder = new StringBuilder();

        // First byte: Format code and PIN length
        pinFieldBuilder.append('0'); // Format code for ISO Format 0
        pinFieldBuilder.append(Integer.toHexString(pin.length()));

        // PIN digits
        pinFieldBuilder.append(pin);

        // Padding with 'F's to make it 16 hex digits (8 bytes)
        while (pinFieldBuilder.length() < 16) {
            pinFieldBuilder.append('F');
        }

        String pinFieldHex = pinFieldBuilder.toString(); // This is the PIN Field in hex
        return HexFormat.of().parseHex(pinFieldHex);
    }

    private byte[] preparePANField(String pan) {
        // Exclude the last digit (check digit)
        String pan12 = pan.substring(pan.length() - 13, pan.length() - 1); // Rightmost 12 digits excluding check digit

        // Construct the PAN Field
        String panFieldHex = "0000" + pan12; // Left-pad with zeros to make it 16 digits (8 bytes)

        // Convert to hexadecimal string
        return HexFormat.of().parseHex(panFieldHex);
    }
}
