package ru.chervoniy.test;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
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
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EsiaSignerTest {

    private static final String BC_PROVIDER = "BC";
    private static final String SIGNING_DATA = "SIGNING_DATA";
    private static final String TEST_CERT_ALIAS = "test_cert";
    private static final String TEST_PASSWORD = "test_password";
    private static final char[] TEST_PASSWORD_ARRAY = "test_password".toCharArray();

    @Test
    void providerAvailable() {
        EsiaSigner.builder().build();
        Provider bcProvider = Security.getProvider(BC_PROVIDER);
        assertNotNull(bcProvider);
    }

    @Test
    void signOk() throws ServiceException, KeyStoreException, OperatorCreationException, CMSException {
        KeyStore store;
        try (InputStream keystoreStream = EsiaSignerTest.class.getResourceAsStream("/test_keystore.jks")) {
            store = KeyStore.getInstance("JKS");
            store.load(keystoreStream, TEST_PASSWORD_ARRAY);
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Supplier<KeyStore> keyStoreSupplier = () -> store;
        EsiaSigner esiaSigner = EsiaSigner.builder()
                .keyStoreSupplier(keyStoreSupplier)
                .privateKeyPasswordSupplier(() -> TEST_PASSWORD)
                .signingCertificateAliasSupplier(() -> TEST_CERT_ALIAS)
                .build();
        String resultSignature = esiaSigner.signPck7Payload(SIGNING_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(resultSignature);
        assertFalse(resultSignature.isEmpty());

        CMSProcessableByteArray cmsProcessableByteArray = new CMSProcessableByteArray(SIGNING_DATA.getBytes());
        byte[] signedByte = Base64.getUrlDecoder().decode(resultSignature);
        CMSSignedData cmsSignedData = new CMSSignedData(cmsProcessableByteArray, signedByte);
        SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
        SignerInformation signerInfo = signerInformationStore.getSigners().iterator().next();

        X509Certificate testCertificate = (X509Certificate) store.getCertificate(TEST_CERT_ALIAS);

        SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(BC_PROVIDER)
                .build(testCertificate.getPublicKey());
        boolean result = signerInfo.verify(signerInformationVerifier);
        assertTrue(result);
    }

}