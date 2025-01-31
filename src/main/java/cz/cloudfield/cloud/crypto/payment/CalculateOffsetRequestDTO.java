package cz.cloudfield.cloud.crypto.payment;

public record CalculateOffsetRequestDTO (
    String zpkAlias,
    String pinBlock,
    String pvkAlias,
    String pan,
    String pinValidationData,
    String decimalizationTable,
    int pinLength
) {
}
