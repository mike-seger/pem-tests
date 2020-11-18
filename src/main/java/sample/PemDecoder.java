package sample;

import lombok.extern.slf4j.Slf4j;
import no.difi.certvalidator.Validator;
import no.difi.certvalidator.ValidatorBuilder;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.rule.CRLRule;
import no.difi.certvalidator.rule.ExpirationRule;
import no.difi.certvalidator.rule.SigningRule;
import org.cryptacular.util.CertUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Slf4j
public class PemDecoder {
    public static void main(String [] args) throws CertificateException, IOException {
        new PemDecoder().run(args);
    }

    public void run(String [] args) throws CertificateException, IOException {
        for(String arg : args) {
            File pemFile = new File(arg);
                if (pemFile.exists()) {
                    String pemString = new String(Files.readAllBytes(pemFile.toPath()), StandardCharsets.UTF_8);
                    log.info("File: {}", pemFile);
                    decode(pemString);
                } else {
                    log.error("File: {} not found", pemFile);
                }

        }
    }

    private void decode(String pemString) throws CertificateException, IOException {
        String delimiter=pemString.trim().replaceAll("([^B]*).*", "$1");
        pemString = pemString.replace(
            delimiter+"BEGIN CERTIFICATE"+delimiter,
            delimiter+"BEGIN CERTIFICATE"+delimiter+"\r\n")
            .replace(delimiter+"END CERTIFICATE"+delimiter,
                    "\r\n"+delimiter+"END CERTIFICATE"+delimiter+"\r\n")
            ;
        try (InputStream inputStream  =  new ByteArrayInputStream(pemString.getBytes(StandardCharsets.UTF_8))) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inputStream);
            validate(cert);
            String cn = CertUtil.subjectCN(cert);
            log.info("Common Name: {}", cn);
        }
    }

    private void validate(X509Certificate cert) {
        Validator validator = ValidatorBuilder.newInstance()
            .addRule(new ExpirationRule())
            .addRule(new SigningRule())
            .addRule(new CRLRule())
            // .addRule(new OCSPRule())
            .build();
        try {
            validator.validate(cert);
            log.info("Certificate is valid.");
        } catch (CertificateValidationException e) {
            log.error("Certificate validation failed: {}", e.getMessage());
        }
    }
}
