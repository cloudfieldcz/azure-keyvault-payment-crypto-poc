package cz.cloudfield.cloud.crypto.payment;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/api/payment-crypto")
public class PaymentCryptoController {

    private final PaymentCryptoService paymentCryptoService;

    public PaymentCryptoController(PaymentCryptoService paymentCryptoService) {
        this.paymentCryptoService = paymentCryptoService;
    }

    @PostMapping("/verify-arqc")
    public VerifyArqcResponseDTO verifyArqc(@RequestBody VerifyArqcRequestDTO request) throws GeneralSecurityException {
        return paymentCryptoService.verifyArqc(request);
    }

    @PostMapping("/offset")
    public String calculateOffset(@RequestBody CalculateOffsetRequestDTO request) throws GeneralSecurityException {
        return paymentCryptoService.calculateOffset(request);
    }

    @PostMapping("/verify-pin")
    public VerifyPinResponseDTO verifyPin(@RequestBody VerifyPinRequestDTO request) throws GeneralSecurityException {
        return paymentCryptoService.verifyPin(request);
    }
}
