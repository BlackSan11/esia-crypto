[![Maven Central](https://maven-badges.herokuapp.com/maven-central/ru.chervoniy-ba/esia-crypto/badge.svg)](https://maven-badges.herokuapp.com/maven-central/ru.chervoniy-ba/esia-crypto)
[![JavaDoc](https://javadoc.io/badge2/ru.chervoniy-ba/esia-crypto/javadoc.svg)](https://javadoc.io/doc/ru.chervoniy-ba/esia-crypto)

# esia-crypto
 Библиотека предназначена для формирования ГОСТ PKCS 7 подписи при обращении к ЕСИА без использования крипто про или других СКЗИ.
 Для генерации подписи необходимо создать экземпляр класса `EsiaSigner`
 ```
 EsiaSigner esiaSigner = EsiaSigner.builder()
                .keyStoreSupplier(keyStoreSupplier)
                .privateKeyPasswordSupplier(() -> "key_password")
                .signingCertificateAliasSupplier(() -> "cert_alias")
                .build();
```

И сгенерировать подпись:
```
byte[] signatureByteArray = esiaSigner.signPkcs7("DATA FRO SIGNING".getBytes(StandardCharsets.UTF_8));
```
