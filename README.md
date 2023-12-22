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
# Подключение библиотеки:
Gradle:
```
implementation group: 'ru.chervoniy-ba', name: 'esia-crypto', version: '1.0.1'
```

Maven:
```
<dependency>
    <groupId>ru.chervoniy-ba</groupId>
    <artifactId>esia-crypto</artifactId>
    <version>1.0.1</version>
</dependency>
```

More:
```
https://central.sonatype.com/artifact/ru.chervoniy-ba/esia-crypto
```
