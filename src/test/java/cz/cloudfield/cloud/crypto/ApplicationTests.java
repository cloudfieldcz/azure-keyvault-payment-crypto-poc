package cz.cloudfield.cloud.crypto;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
@ActiveProfiles("test")
class ApplicationTests {

	@MockitoBean
	private CryptographyProvider cryptographyProvider;

	@Test
	void contextLoads() {
	}
}
