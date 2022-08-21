package ru.chervoniy;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import ru.chervoniy.exception.ServiceException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
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
import java.util.Base64;
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

    public String signPck7Payload(byte[] payload) throws ServiceException {
        CMSTypedData cmsData = new CMSProcessableByteArray(payload);
        try {
            CMSSignedDataGenerator signatureProvider = getSignatureProvider();
            boolean detached = this.detachedFlagSupplier.get();
            CMSSignedData signedData = signatureProvider.generate(cmsData, !detached);
            byte[] signedDataEncoded = signedData.getEncoded();
            ASN1Primitive asn1Primitive = ASN1Primitive.fromByteArray(signedDataEncoded);
            ContentInfo contentInfo = ContentInfo.getInstance(asn1Primitive);
            StringWriter stringWriter = new StringWriter();
            JcaPEMWriter writer = new JcaPEMWriter(stringWriter);
            writer.writeObject(contentInfo);
            writer.close();
            String pemPayload = stringWriter.toString();
            try (StringReader stringReader = new StringReader(pemPayload);
                 PemReader pemReader = new PemReader(stringReader)) {
                PemObject pemObject = pemReader.readPemObject();
                return Base64.getUrlEncoder().encodeToString(pemObject.getContent());
            } catch (IOException e) {
                throw new ServiceException(e.getMessage(), e);
            }
        } catch (CMSException | IOException e) {
            throw new ServiceException("Unable to sign payload", e);
        }
    }

    private CMSSignedDataGenerator getSignatureProvider() throws ServiceException {
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
            throw new ServiceException("Unable to create signature generator", e);
        }
        return signedDataGenerator;
    }

    private Deque<X509Certificate> getCertificateChain() throws ServiceException {
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
            throw new ServiceException("Unable to load certificates from chain", e);
        }
    }

}
