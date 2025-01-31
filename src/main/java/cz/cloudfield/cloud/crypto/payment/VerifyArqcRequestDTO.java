package cz.cloudfield.cloud.crypto.payment;

public record VerifyArqcRequestDTO(
    String imkAlias,
    String emvTransactionData, // without additional padding
    String atc, // same as is in emvTransactionData
    String pan,
    String panSeqNumber,
    byte[] arqc) {
}
