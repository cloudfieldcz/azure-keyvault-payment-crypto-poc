package cz.cloudfield.cloud.crypto.utils;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

public class PinOffsetHelper {

    private final SecretKey pvk;
    private final SecretKey zpk;

    public PinOffsetHelper(SecretKey pvk, SecretKey zpk) {
        this.pvk = pvk;
        this.zpk = zpk;
    }

    public String extractPinFromPinBlock(String pinBlock, String pan) throws GeneralSecurityException {
        byte[] pinBlockBytes = HexFormat.of().parseHex(pinBlock);
        if (pinBlockBytes.length != 8) {
            throw new IllegalArgumentException("Invalid PIN block length: " + pinBlockBytes.length);
        }

        byte[] pinBlockDecrypted = CryptoUtils.decrypt(zpk, pinBlockBytes);

        byte[] panField = preparePanField(pan);

        // XOR the decrypted PIN Block with the PAN Block to get the PIN Field
        byte[] pinField = new byte[8];
        for (int i = 0; i < 8; i++) {
            pinField[i] = (byte) (pinBlockDecrypted[i] ^ panField[i]);
        }

        // Convert PIN field to hexadecimal string
        String pinFieldHex = HexFormat.of().withUpperCase().formatHex(pinField);

        // Extract the PIN length from the second nibble
        int pinLength = Character.digit(pinFieldHex.charAt(1), 16);

        // Validate PIN length
        if (pinLength < 4 || pinLength > 12) {
            throw new IllegalArgumentException("Invalid PIN length extracted from PIN Block.");
        }

        // Extract the PIN digits
        StringBuilder pinBuilder = new StringBuilder();
        for (int i = 2; i < 2 + pinLength; i++) {
            char c = pinFieldHex.charAt(i);
            if (c == 'F') {
                break; // Stop if padding character 'F' is encountered
            }
            pinBuilder.append(c);
        }

        return pinBuilder.toString();
    }

    private byte[] preparePanField(String pan) {
        // Exclude the last digit (check digit)
        String pan12 = pan.substring(pan.length() - 13, pan.length() - 1); // Rightmost 12 digits excluding check digit

        // Build the PAN field (16 hex digits)
        String panBlockString = "0000" + pan12;

        // Convert PAN Block to byte array
        return HexFormat.of().parseHex(panBlockString);
    }

    public String calculateNaturalPin(String pan, String decimalizationTable, String pinValidationData, int pinLength) throws GeneralSecurityException {
        byte[] pvd = HexFormat.of().parseHex(pinValidationData.replace("N", pan.substring(pan.length() - 5)));
        if (pvd.length != 8) {
            throw new IllegalArgumentException("Invalid PVD length: " + pvd.length);
        }

        byte[] pvdEncrypted = CryptoUtils.encrypt(pvk, pvd);

        // Convert encrypted data to hexadecimal string
        String pvdEncryptedHex = HexFormat.of().withUpperCase().formatHex(pvdEncrypted);

        // Decimalize using the decimalization table
        StringBuilder decimalized = new StringBuilder();
        for (int i = 0; i < pvdEncryptedHex.length(); i++) {
            char hexChar = pvdEncryptedHex.charAt(i);
            int index = Character.digit(hexChar, 16);
            decimalized.append(decimalizationTable.charAt(index));
        }

        // Extract the Natural PIN
        return decimalized.substring(0, pinLength);
    }

    // Function to calculate offset
    public String calculateOffset(String naturalPin, String enteredPin) {
        int pinLength = naturalPin.length();
        StringBuilder offsetBuilder = new StringBuilder();
        for (int i = 0; i < pinLength; i++) {
            int natDigit = Character.digit(naturalPin.charAt(i), 10);
            int enteredDigit = Character.digit(enteredPin.charAt(i), 10);
            int offsetDigit = ((natDigit - enteredDigit + 10) % 10);
            offsetBuilder.append(offsetDigit);
        }

        // Padding with 'F's to make it 12 hex digits (6 bytes)
        while (offsetBuilder.length() < 12) {
            offsetBuilder.append('F');
        }

        return offsetBuilder.toString();
    }

    public String calculateExpectedPin(String naturalPin, String pinOffset) {
        int pinLength = naturalPin.length();
        String offset = pinOffset.substring(0, pinLength);

        StringBuilder expectedPINBuilder = new StringBuilder();
        for (int i = 0; i < pinLength; i++) {
            int natDigit = Character.digit(naturalPin.charAt(i), 10);
            int offsetDigit = Character.digit(offset.charAt(i), 10);
            int expectedDigit = (natDigit + 10 - offsetDigit) % 10;
            expectedPINBuilder.append(expectedDigit);
        }
        return expectedPINBuilder.toString();
    }

}
