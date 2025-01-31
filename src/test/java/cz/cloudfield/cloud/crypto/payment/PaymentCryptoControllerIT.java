package cz.cloudfield.cloud.crypto.payment;

import com.fasterxml.jackson.databind.ObjectMapper;
import cz.cloudfield.cloud.crypto.CryptographyProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class PaymentCryptoControllerIT {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PinBlockConstructor pinBlockConstructor;

    @MockitoBean
    private CryptographyProvider cryptographyProvider;

    @Test
    void calculateOffset() throws Exception {
        String pin = "1234";
        String pan = "6203011199415646";

        String pinBlock = pinBlockConstructor.constructPinBlock(pin, pan);

        CalculateOffsetRequestDTO request = new CalculateOffsetRequestDTO(
            "zpk-tdes",
            pinBlock,
            "pvk-tdes",
            pan,
            "123456N12345",
            "1234567890987654",
            4
        );

        MvcResult encryptResult = mockMvc.perform(post("/api/payment-crypto/offset")
                .content(objectMapper.writeValueAsBytes(request))
                .contentType(APPLICATION_JSON))
            .andExpectAll(status().isOk())
            .andReturn();

        String offset = encryptResult.getResponse().getContentAsString();
        assertNotNull(offset);
        assertEquals("5740FFFFFFFF", offset);
    }

    @Test
    void verifyPin() throws Exception {
        String pin = "1234";
        String pan = "6203011199415646";

        String pinBlock = pinBlockConstructor.constructPinBlock(pin, pan);

        VerifyPinRequestDTO request = new VerifyPinRequestDTO(
            "zpk-tdes",
            pinBlock,
            "pvk-tdes",
            pan,
            "123456N12345",
            "1234567890987654",
            4,
            "5740FFFFFFFF"
        );

        MvcResult encryptResult = mockMvc.perform(post("/api/payment-crypto/verify-pin")
                .content(objectMapper.writeValueAsBytes(request))
                .contentType(APPLICATION_JSON))
            .andExpectAll(status().isOk())
            .andReturn();

        VerifyPinResponseDTO response = objectMapper.readValue(encryptResult.getResponse().getContentAsString(), VerifyPinResponseDTO.class);
        assertNotNull(response);
        assertTrue(response.pinVerificationResult());
    }
}
