package ru.chervoniy;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import ru.chervoniy.exception.EsiaSignerException;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.Supplier;

public class EsiaSigner {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final Supplier<String> signingAlgorithmSupplier;
    private final Supplier<String> signatureProviderSupplier;
    private final Supplier<KeyStore> keyStoreSupplier;
    private final Supplier<String> signingCertificateAliasSupplier;
    private final Supplier<String> privateKeyPasswordSupplier;
    private final Supplier<Boolean> detachedFlagSupplier;

    EsiaSigner(Supplier<String> signingAlgorithmSupplier, Supplier<String> signatureProviderSupplier,
               Supplier<KeyStore> keyStoreSupplier, Supplier<String> signingCertificateAliasSupplier,
               Supplier<String> privateKeyPasswordSupplier, Supplier<Boolean> detachedFlagSupplier) {
        this.signingAlgorithmSupplier = signingAlgorithmSupplier;
        this.signatureProviderSupplier = signatureProviderSupplier;
        this.keyStoreSupplier = keyStoreSupplier;
        this.signingCertificateAliasSupplier = signingCertificateAliasSupplier;
        this.privateKeyPasswordSupplier = privateKeyPasswordSupplier;
        this.detachedFlagSupplier = detachedFlagSupplier;
    }

    public static EsiaSignerBuilder builder() {
        return EsiaSignerBuilder.builder();
    }

    /**
     * @param payload data for signing, not base64, only raw data bytes
     * @return signature byte array
     * @throws EsiaSignerException if error occur in signature generating
     */
    public byte[] signPkcs7(byte[] payload) throws EsiaSignerException {
        CMSTypedData cmsData = new CMSProcessableByteArray(payload);
        try {
            CMSSignedDataGenerator signatureProvider = getSignatureProvider();
            boolean detached = this.detachedFlagSupplier.get();
            CMSSignedData signedData = signatureProvider.generate(cmsData, !detached);
            return signedData.getEncoded();
        } catch (CMSException | IOException e) {
            throw new EsiaSignerException("Unable to sign payload", e);
        }
    }

    private CMSSignedDataGenerator getSignatureProvider() throws EsiaSignerException {
        KeyStore keyStore = keyStoreSupplier.get();
        Deque<X509Certificate> certificateChain = getCertificateChain();
        String keystorePassword = privateKeyPasswordSupplier.get();
        char[] keystorePasswordChars = keystorePassword.toCharArray();
        X509Certificate certificateForSign = certificateChain.getFirst();
        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
        try {
            String certificateAliasSupplier = signingCertificateAliasSupplier.get();
            Key key = keyStore.getKey(certificateAliasSupplier, keystorePasswordChars);
            String signatureProvider = signatureProviderSupplier.get();
            ContentSigner contentSigner = new JcaContentSignerBuilder(signingAlgorithmSupplier.get())
                    .setProvider(signatureProvider)
                    .build(((PrivateKey) key));
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(signatureProvider)
                    .build();
            SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                    .build(contentSigner, certificateForSign);
            signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
            byte[] certificateData = certificateForSign.getEncoded();
            X509CertificateHolder certificate = new X509CertificateHolder(certificateData);
            signedDataGenerator.addCertificate(certificate);
        } catch (OperatorCreationException | CertificateEncodingException | UnrecoverableKeyException | KeyStoreException
                 | NoSuchAlgorithmException | IOException | CMSException e) {
            throw new EsiaSignerException("Unable to create signature generator", e);
        }
        return signedDataGenerator;
    }

    private Deque<X509Certificate> getCertificateChain() throws EsiaSignerException {
        try {
            Deque<X509Certificate> certificateDeque = new ArrayDeque<>();
            KeyStore keyStore = keyStoreSupplier.get();
            String signingCertificateAlias = signingCertificateAliasSupplier.get();
            Certificate[] certificateChain = keyStore.getCertificateChain(signingCertificateAlias);
            for (Certificate certificate : certificateChain) {
                certificateDeque.add((X509Certificate) certificate);
            }
            return certificateDeque;
        } catch (KeyStoreException e) {
            throw new EsiaSignerException("Unable to load certificates from chain", e);
        }
    }

}
