# esia-crypto
 Библиотека предназначена для формирования ГОСТ PKCS 7 подписи при обращении к ЕСИА без использования крипто про.
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
