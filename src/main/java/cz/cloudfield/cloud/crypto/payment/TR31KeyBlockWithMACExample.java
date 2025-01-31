package cz.cloudfield.cloud.crypto.payment;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.Arrays;

import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class TR31KeyBlockWithMACExample {

    public static void main(String[] args) throws Exception {

        // Step 0: Add Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());

        // Step 1: Define the TDES key and the AES KEK
        // Example TDES key (16 bytes for double-length key)
        String tdesKeyHex = "0123456789ABCDEFFEDCBA9876543210";
        byte[] tdesKeyBytes = Hex.decode(tdesKeyHex);
        SecretKey tdesKey = new SecretKeySpec(tdesKeyBytes, "DESede");

        // Example AES KEK (32 bytes for 256-bit key)
        String aesKekHex = "000102030405060708090A0B0C0D0E0F"
            + "101112131415161718191A1B1C1D1E1F";
        byte[] aesKekBytes = Hex.decode(aesKekHex);
        SecretKey aesKek = new SecretKeySpec(aesKekBytes, "AES");

        // Step 2: Construct the TR-31 header
        byte[] header = constructTR31Header();

        // Step 3: Wrap the TDES key using AES Key Wrap
        byte[] wrappedKey = wrapKeyUsingAESKeyWrap(tdesKeyBytes, aesKekBytes);

        // Step 4: Calculate the MAC over the header and wrapped key
        byte[] mac = calculateCMAC(header, wrappedKey, aesKekBytes);

        // Step 5: Assemble the key block (header + wrapped key + MAC)
        byte[] keyBlock = concatenate(header, wrappedKey, mac);

        // Step 6: Display the TR-31 Key Block in hexadecimal
        String keyBlockHex = Hex.toHexString(keyBlock).toUpperCase();
        System.out.println("TR-31 Key Block (Hex):");
        System.out.println(keyBlockHex);

        // Optional: Verify the MAC
        boolean macValid = verifyCMAC(header, wrappedKey, mac, aesKekBytes);
        System.out.println("MAC Verification Result: " + (macValid ? "Valid" : "Invalid"));
    }

    // Function to construct the TR-31 header
    public static byte[] constructTR31Header() {
        // TR-31 header is 16 bytes long
        byte[] header = new byte[16];

        // Header Identifier: 'B0' (2 bytes)
        header[0] = (byte) 'B';
        header[1] = (byte) '0';

        // Version ID: '04' (2 bytes)
        header[2] = (byte) '0';
        header[3] = (byte) '4';

        // Key Usage: 'D0' (2 bytes) - Data encryption/decryption key
        header[4] = (byte) 'D';
        header[5] = (byte) '0';

        // Algorithm Identifier: 'T' (1 byte) - TDES key
        header[6] = (byte) 'T';

        // Key Length: '1' (1 byte) - Double-length key (16 bytes)
        header[7] = (byte) '1';

        // Protection Mode: 'U0' (2 bytes) - AES Key Wrap with AES KEK
        header[8] = (byte) 'U';
        header[9] = (byte) '0';

        // Reserved: '000000' (6 bytes)
        for (int i = 10; i < 16; i++) {
            header[i] = (byte) '0';
        }

        return header;
    }

    // Function to wrap the key using AES Key Wrap
    public static byte[] wrapKeyUsingAESKeyWrap(byte[] keyToWrap, byte[] kekBytes) throws Exception {
        // Initialize the cipher for AES Key Wrap
        SecretKey kek = new SecretKeySpec(kekBytes, "AES");
        Cipher cipher = Cipher.getInstance("AESWrap", "BC"); // 'BC' for Bouncy Castle
        cipher.init(Cipher.WRAP_MODE, kek);

        // Wrap the key
        byte[] wrappedKey = cipher.wrap(new SecretKeySpec(keyToWrap, "DESede"));
        return wrappedKey;
    }

    // Function to calculate CMAC over the header and wrapped key
    public static byte[] calculateCMAC(byte[] header, byte[] wrappedKey, byte[] macKeyBytes) throws Exception {
        // Initialize CMAC with AES
        KeyParameter key = new KeyParameter(macKeyBytes);
        CMac cmac = new CMac(new org.bouncycastle.crypto.engines.AESEngine());
        cmac.init(key);

        // Update CMAC with header and wrapped key
        cmac.update(header, 0, header.length);
        cmac.update(wrappedKey, 0, wrappedKey.length);

        // Finalize CMAC calculation
        byte[] mac = new byte[16]; // CMAC output is 16 bytes for AES
        cmac.doFinal(mac, 0);

        // TR-31 specifies an 8-byte MAC, so truncate if necessary
        byte[] truncatedMac = Arrays.copyOf(mac, 8);
        return truncatedMac;
    }

    // Function to verify the CMAC
    public static boolean verifyCMAC(byte[] header, byte[] wrappedKey, byte[] receivedMac, byte[] macKeyBytes) throws Exception {
        byte[] calculatedMac = calculateCMAC(header, wrappedKey, macKeyBytes);
        return Arrays.equals(receivedMac, calculatedMac);
    }

    // Helper function to concatenate multiple byte arrays
    public static byte[] concatenate(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            totalLength += arr.length;
        }

        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, currentIndex, arr.length);
            currentIndex += arr.length;
        }
        return result;
    }
}

