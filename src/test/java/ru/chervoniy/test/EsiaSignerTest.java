package ru.chervoniy.test;

import org.junit.jupiter.api.Test;
import ru.chervoniy.EsiaSigner;
import ru.chervoniy.exception.ServiceException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class EsiaSignerTest {

    private static final String TEST_CERT_ALIAS = "test_cert";
    private static final String TEST_PASSWORD = "test_password";
    private static final char[] TEST_PASSWORD_ARRAY = "test_password".toCharArray();

    @Test
    void providerAvailable() {
        EsiaSigner.builder().build();
        Provider bcProvider = Security.getProvider("BC");
        assertNotNull(bcProvider);
    }

    @Test
    void signOk() throws ServiceException, IOException {
        Supplier<KeyStore> keyStoreSupplier = () -> {
            try (InputStream keystoreStream = EsiaSignerTest.class.getResourceAsStream("/test_keystore.jks")) {
                KeyStore store = KeyStore.getInstance("JKS");
                store.load(keystoreStream, TEST_PASSWORD_ARRAY);
                return store;
            } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        };
        EsiaSigner esiaSigner = EsiaSigner.builder()
                .keyStoreSupplier(keyStoreSupplier)
                .privateKeyPasswordSupplier(() -> TEST_PASSWORD)
                .signingCertificateAliasSupplier(() -> TEST_CERT_ALIAS)
                .build();
        String resultSignature = esiaSigner.signPck7Payload("SIGNING_DATA".getBytes(StandardCharsets.UTF_8));
        System.out.println(resultSignature);
        try (InputStream expectedSignatureStream = EsiaSignerTest.class.getResourceAsStream("/expected.signature")) {
            assert expectedSignatureStream != null;
            String expectedSignature = new String(expectedSignatureStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}