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
import ru.chervoniy.exception.EsiaSignerException;

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
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EsiaSignerTest {

    private static final String TEST_CERT_ALIAS = "test_cert";
    private static final String SIGNING_DATA = "SIGNING_DATA";
    private static final String TEST_PASSWORD = "test_password";
    private static final String DEFAULT_SIGNATURE_PROVIDER = "BC";
    private static final char[] TEST_PASSWORD_ARRAY = "test_password".toCharArray();

    @Test
    void providerAvailable() {
        EsiaSigner.builder().build();
        Provider bcProvider = Security.getProvider(DEFAULT_SIGNATURE_PROVIDER);
        assertNotNull(bcProvider);
    }

    @Test
    void signOk() throws EsiaSignerException, KeyStoreException, OperatorCreationException, CMSException {
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
        byte[] resultSignature = esiaSigner.signPkcs7(SIGNING_DATA.getBytes(StandardCharsets.UTF_8));
        KeyStore keyStore = keyStoreSupplier.get();
        X509Certificate certificateForVerify = (X509Certificate) keyStore.getCertificate(TEST_CERT_ALIAS);

        CMSSignedData cmsSignedData =
                new CMSSignedData(new CMSProcessableByteArray((SIGNING_DATA).getBytes(StandardCharsets.UTF_8)), resultSignature);
        SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
        SignerInformation signerInfo = signerInformationStore.getSigners().iterator().next();

        SignerInformationVerifier signVerifier = new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(DEFAULT_SIGNATURE_PROVIDER)
                .build(certificateForVerify);
        boolean verifyResult = signerInfo.verify(signVerifier);
        assertTrue(verifyResult);
    }

}