package cz.cloudfield.cloud.crypto.payment;

import cz.cloudfield.cloud.crypto.key.KeyManager;
import cz.cloudfield.cloud.crypto.utils.CryptogramCalculator;
import cz.cloudfield.cloud.crypto.utils.PinOffsetHelper;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

@Service
public class PaymentCryptoServiceImpl implements PaymentCryptoService {

    private final KeyManager keyManager;

    public PaymentCryptoServiceImpl(KeyManager keyManager) {
        this.keyManager = keyManager;
    }


    @Override
    public VerifyArqcResponseDTO verifyArqc(VerifyArqcRequestDTO request) throws GeneralSecurityException {
        SecretKey imk = keyManager.getKey(request.imkAlias(), "01");

        byte[] calculated = CryptogramCalculator.calculateARQC(imk, request.pan(), request.panSeqNumber(), request.emvTransactionData(), request.atc());

        boolean arqcVerificationResult = MessageDigest.isEqual(calculated, request.arqc());

        return new VerifyArqcResponseDTO(arqcVerificationResult);
    }

    @Override
    public String calculateOffset(CalculateOffsetRequestDTO request) throws GeneralSecurityException {
        SecretKey pvk = keyManager.getKey(request.pvkAlias(), "01");
        SecretKey zpk = keyManager.getKey(request.zpkAlias(), "01");

        PinOffsetHelper pinOffsetHelper = new PinOffsetHelper(pvk, zpk);

        // Extract entered PIN from the PIN block
        String enteredPIN = pinOffsetHelper.extractPinFromPinBlock(request.pinBlock(), request.pan());

        // Calculate natural PIN
        String naturalPin = pinOffsetHelper.calculateNaturalPin(request.pan(), request.decimalizationTable(), request.pinValidationData(), request.pinLength());

        // Offset calculation
        return pinOffsetHelper.calculateOffset(naturalPin, enteredPIN);
    }

    @Override
    public VerifyPinResponseDTO verifyPin(VerifyPinRequestDTO request) throws GeneralSecurityException {
        SecretKey pvk = keyManager.getKey(request.pvkAlias(), "01");
        SecretKey zpk = keyManager.getKey(request.zpkAlias(), "01");

        PinOffsetHelper pinOffsetHelper = new PinOffsetHelper(pvk, zpk);

        // Extract entered PIN from the PIN block
        String enteredPin = pinOffsetHelper.extractPinFromPinBlock(request.pinBlock(), request.pan());

        // Calculate natural PIN
        String naturalPin = pinOffsetHelper.calculateNaturalPin(request.pan(), request.decimalizationTable(), request.pinValidationData(), request.pinLength());

        // Calculate Expected PIN
        String expectedPin = pinOffsetHelper.calculateExpectedPin(naturalPin, request.offset());

        boolean pinVerificationResult = enteredPin.equals(expectedPin);

        return new VerifyPinResponseDTO(pinVerificationResult);
    }
}
