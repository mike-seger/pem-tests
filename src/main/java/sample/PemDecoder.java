package sample;

import lombok.extern.slf4j.Slf4j;
import org.cryptacular.util.CertUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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
            if(pemFile.exists()) {
                log.info("File: {}", pemFile);
                decode(pemFile);
            } else {
                log.error("File: {} not found", pemFile);
            }
        }
    }

    public void decode(File pemFile) throws CertificateException, IOException {
        FileInputStream inputStream  =  new FileInputStream (pemFile);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)certFactory.generateCertificate(inputStream);
        String cn = CertUtil.subjectCN(cert);
        log.info("Common Name: {}", cn);
    }
}
