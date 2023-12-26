package ru.chervoniy;

import java.security.KeyStore;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

public class EsiaSignerBuilder {

    private static final String DEFAULT_SIGNATURE_PROVIDER = "BC";
    private static final String DEFAULT_SIGNATURE_ALGORITHM = "GOST3411-2012-256WITHECGOST3410-2012-256";

    private Supplier<String> signingAlgorithmSupplier = () -> DEFAULT_SIGNATURE_ALGORITHM;
    private Supplier<String> signatureProviderSupplier = () -> DEFAULT_SIGNATURE_PROVIDER;
    private Supplier<KeyStore> keyStoreSupplier;
    private Supplier<String> signingCertificateAliasSupplier;
    private Supplier<String> privateKeyPasswordSupplier;
    private BooleanSupplier detachedFlagSupplier = () -> true;

    static EsiaSignerBuilder builder() {
        return new EsiaSignerBuilder();
    }

    /**
     * @param signingAlgorithmSupplier signature algorithm, default = {@value DEFAULT_SIGNATURE_ALGORITHM}
     * @return this
     */
    public EsiaSignerBuilder signingAlgorithmSupplier(Supplier<String> signingAlgorithmSupplier) {
        this.signingAlgorithmSupplier = signingAlgorithmSupplier;
        return this;
    }

    /**
     * @param signatureProviderSupplier signature algorithm, default = {@value DEFAULT_SIGNATURE_PROVIDER}
     * @return this
     */
    public EsiaSignerBuilder signatureProviderSupplier(Supplier<String> signatureProviderSupplier) {
        this.signatureProviderSupplier = signatureProviderSupplier;
        return this;
    }

    /**
     * Keystore supplier example:
     * <pre>{@code
     * Supplier<KeyStore> keystoreSupplier = () -> {
     *      try (InputStream stream = new FileInputStream("path/to/keystore.p12")) {
     *          KeyStore store = KeyStore.getInstance("PKCS12");
     *          store.load(stream, "p@ssword".toCharArray());
     *          return store;
     *      } catch (Exception e) {
     *          log.error("Keystore loading error", e);
     *          throw new RuntimeException(e);
     *      }
     * };
     * }</pre>
     *
     * @param keyStoreSupplier key store supplier
     * @return this
     */
    public EsiaSignerBuilder keyStoreSupplier(Supplier<KeyStore> keyStoreSupplier) {
        this.keyStoreSupplier = keyStoreSupplier;
        return this;
    }

    /**
     * @param signingCertificateAliasSupplier certificate alias for signing, which is located in keystore from {@link #keyStoreSupplier}
     * @return this
     */
    public EsiaSignerBuilder signingCertificateAliasSupplier(Supplier<String> signingCertificateAliasSupplier) {
        this.signingCertificateAliasSupplier = signingCertificateAliasSupplier;
        return this;
    }

    /**
     * @param privateKeyPasswordSupplier password for private key which is located in keystore from {@link #keyStoreSupplier} and using
     *                                   for sign
     * @return this
     */
    public EsiaSignerBuilder privateKeyPasswordSupplier(Supplier<String> privateKeyPasswordSupplier) {
        this.privateKeyPasswordSupplier = privateKeyPasswordSupplier;
        return this;
    }

    /**
     * @param detachedFlagSupplier signature detached flag, default = true
     * @return this
     */
    public EsiaSignerBuilder detachedFlagSupplier(BooleanSupplier detachedFlagSupplier) {
        this.detachedFlagSupplier = detachedFlagSupplier;
        return this;
    }

    public EsiaSigner build() {
        return new EsiaSigner(this.signingAlgorithmSupplier, this.signatureProviderSupplier, this.keyStoreSupplier,
                this.signingCertificateAliasSupplier, this.privateKeyPasswordSupplier, this.detachedFlagSupplier);
    }

}
