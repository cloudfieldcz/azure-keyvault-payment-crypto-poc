package cz.cloudfield.cloud.crypto.utils;

import org.bouncycastle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

import static cz.cloudfield.cloud.crypto.utils.CryptoUtils.xor;

/**
 * @author david.svamberk
 */
public class CryptogramCalculator {

    /**
     * <p>
     * Calculates ARQC - Authorisation Request Cryptogram.
     * Cryptogram is calculated as MAC of transaction data.
     * </p>
     *
     * <p>
     * EMV v4.3 Book 2 Security and Key Management
     * A1.2.2 MAC Algorithms using an 16-byte block cipher
     * </p>
     *
     * <ol>
     *     <li>Pad transaction data.</li>
     *     <li>Split transaction data to 16-byte blocks.</li>
     *     <li>Derive UDK from IMK, PAN and PANSeqNo</li>
     *     <li>Derive Session key from UDK and ATC</li>
     *     <li>Calculate MAC.</li>
     * </ol>
     *
     * @param imk            - Issuer Master Key (IMK-AC)
     * @param pan            - PAN of card
     * @param panSeqNumber   - PAN sequence number from card
     * @param cryptogramData - Transaction Data
     * @param atc            - Application Transaction Counter
     * @return ARQC (calculated MAC)
     * @throws GeneralSecurityException when calculation fails
     */
    public static byte[] calculateARQC(SecretKey imk, String pan, String panSeqNumber, String cryptogramData, String atc) throws GeneralSecurityException {
        int blockSize = 16;

        SecretKey udk = deriveUDK(pan, panSeqNumber, imk);

        SecretKey sessionKey = deriveSessionKey(HexFormat.of().parseHex(atc), udk);

        // TRX := (TRX || '80' || '00' || '00' || . . . || '00')
        String trxDataPadded = CryptoUtils.addIsoPadding(cryptogramData, blockSize);

        // TRX is then divided into 16-byte blocks X1, X2, . . . , XB.
        String[] dataBlocks = trxDataPadded.split("(?<=\\G.{" + blockSize * 2 + "})");

        // If no padding was added
        if (trxDataPadded.equals(cryptogramData)) {
            // Let Z be 16-bytes set to zero.
            byte[] z = new byte[blockSize];

            // Let C be equal to Z except with its least significant bits set to ‘10000111’
            // (C is a CMAC-defined constant for a 16-byte block cipher).
            byte[] c = Arrays.copyOf(z, blockSize);
            c[c.length - 1] = (byte) 0x87;

            //L := ALG(KS)[Z]
            byte[] l = CryptoUtils.encrypt(sessionKey, z);

            // K1 = L << 1.
            BigInteger lBi = new BigInteger(l);
            BigInteger key1Bi = lBi.shiftLeft(1);
            byte[] key1 = key1Bi.toByteArray();
            // If msb(L) = 1 then K1 := K1 ^ C
            if (lBi.testBit(0)) {
                key1 = xor(key1, c);
            }

            // K2 = K1 << 1.
            BigInteger key2Bi = new BigInteger(key1).shiftLeft(1);
            byte[] key2 = key2Bi.toByteArray();
            // If msb(K1) = 1 then K2 := K2 ^ C
            if (key1Bi.testBit(0)) {
                key2 = xor(key2, c);
            }

            // Mask the final block with sub-key K1
            // XB := XB ^ K1
            // and with sub-key K2
            // XB := XB ^ K2
            byte[] last = HexFormat.of().parseHex(dataBlocks[dataBlocks.length - 1]);
            last = xor(last, key1);
            last = xor(last, key2);
            dataBlocks[dataBlocks.length - 1] = HexFormat.of().withUpperCase().formatHex(last);
        }

        // Initial value of MAC - H0 := ('00' || '00' || ... || '00' || '00')
        byte[] arqc = new byte[blockSize];

        // Hi := ALG(KSL)[Xi XOR Hi-1], for i = 1, 2, . . . , B
        for (String dataBlock : dataBlocks) {
            byte[] data = HexFormat.of().parseHex(dataBlock);
            byte[] xor = xor(data, arqc);
            arqc = CryptoUtils.encrypt(sessionKey, xor);
        }

        return Arrays.copyOfRange(arqc, 0, 8);
    }

    /**
     * <p>
     * Derives UDK (Unique Derived Key) / MS (Master key) from given data encryption key/Issuer master key,
     * PAN and PAN sequence number.
     * </p>
     *
     * <p>
     * EMV v4.3 Book 2 Security and Key Management
     * A1.4 Master Key Derivation - A1.4.3 Option C - AES
     * </p>
     *
     * <ol>
     *  <li>Derive first part of UDK - Encrypt PAN + PANSeqNo with key</li>
     *  <li>
     *      Derive second part of UDK - Encrypt (PAN + PANSeqNo XOR 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
     *      with key
     *  </li>
     *  <li>Compose UDK from parts</li>
     * </ol>
     *
     * @param pan          - PAN of card
     * @param panSeqNumber - PAN sequence number from card
     * @param key          - {@link SecretKey} data encryption key/Issuer master key
     * @return derived UDK {@link SecretKey}
     * @throws GeneralSecurityException when derivation fails
     */
    public static SecretKey deriveUDK(String pan, String panSeqNumber, SecretKey key) throws GeneralSecurityException {
        String panAndSeqNo = pan + panSeqNumber;

        // Concatenate from left to right the decimal digits of the Application PAN with
        // the PAN Sequence Number.
        byte[] data = HexFormat.of().parseHex(panAndSeqNo.length() % 2 == 0 ? panAndSeqNo : "0" + panAndSeqNo);

        // Pad it to the left with hexadecimal zeros in order to obtain a 16-byte number
        // Y in numeric format.
        byte[] yValue = CryptoUtils.leftPaddToMultipleOf(16, data, (byte) 0x00);

        // Derive first part of UDK -> firstUDK := AES(IMK)[Y]
        byte[] firstUDK = CryptoUtils.encrypt(key, yValue);

        // Y* = Y ^ ('FF' || 'FF' || ... || 'FF' || 'FF').
        byte[] fs = new byte[16];
        Arrays.fill(fs, (byte) 0xFF);

        byte[] xor = xor(yValue, fs);

        // Derive second part of UDK -> secondUDK := AES(IMK)[Y*]
        byte[] secondUDK = CryptoUtils.encrypt(key, xor);

        // Final Unique Derived Key -> UDK := {AES(IMK)[Y] || AES(IMK)[Y*]}
        byte[] udk = Arrays.concatenate(firstUDK, secondUDK);

        return new SecretKeySpec(udk, "AES");
    }

    /**
     * <p>
     * Derives Common Session Key from given Application Transaction Counter and Unique Derivation Key.
     * </p>
     *
     * <p>
     * EMV v4.3 Book 2 Security and Key Management
     * Derivation algorithm according to A1.3.1 Common Session Key Derivation Option.
     * </p>
     *
     * @param atc - Application Transaction Counter
     * @param udk - {@link SecretKey} Unique Derivation Key
     * @return derived session key {@link SecretKey}
     * @throws GeneralSecurityException when derivation fails
     */
    public static SecretKey deriveSessionKey(byte[] atc, SecretKey udk) throws GeneralSecurityException {
        //For the session key used to generate and verify the Application Cryptogram and the ARPC,
        // the diversification value is the ATC followed by n-2 bytes of '00':
        //    R := ATC || '00' || '00' || … || '00' || '00' || '00'.
        byte[] padding = new byte[13]; // 16 - ATC(2Byte) - 0F/F0(1Byte) = 13

        //F1 = R0 || R1 || 'F0' || … || Rn-1.
        byte[] first = Arrays.concatenate(atc, new byte[]{(byte) 0xF0}, padding);

        // F2 = R0 || R1 || '0F' || … || Rn-1.
        byte[] second = Arrays.concatenate(atc, new byte[]{(byte) 0x0F}, padding);

        // {ALG (MK) [F1] || ALG (MK) [F2] }.
        byte[] sk = Arrays.concatenate(CryptoUtils.encrypt(udk, first), CryptoUtils.encrypt(udk, second));

        return new SecretKeySpec(sk, "AES");
    }
}
