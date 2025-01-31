package cz.cloudfield.cloud.crypto.payment;

public record VerifyPinRequestDTO(
    String zpkAlias,
    String pinBlock,
    String pvkAlias,
    String pan,
    String pinValidationData,
    String decimalizationTable,
    int pinLength,
    String offset
) {
}
