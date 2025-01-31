package cz.cloudfield.cloud.crypto.payment;

import java.security.GeneralSecurityException;

public interface PaymentCryptoService {

    VerifyArqcResponseDTO verifyArqc(VerifyArqcRequestDTO request) throws GeneralSecurityException;

    String calculateOffset(CalculateOffsetRequestDTO request) throws GeneralSecurityException;

    VerifyPinResponseDTO verifyPin(VerifyPinRequestDTO request) throws GeneralSecurityException;
}
