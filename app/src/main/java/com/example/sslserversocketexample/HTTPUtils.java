package com.example.sslserversocketexample;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.content.res.AssetManager;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HTTPUtils {

    public static String createBKSFile(Context mainContext, String password) {

        //create Certification file using the value saved in your app_name string
        final String fileName = mainContext.getFilesDir().getPath() + "/" + mainContext.getString(R.string.app_name).replace(" ","_") + ".bks";

        try {
            Security.addProvider(new BouncyCastleProvider());

            final java.security.KeyPairGenerator rsaKeyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
            rsaKeyPairGenerator.initialize(2048);
            final KeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();

            final KeyStore ks = KeyStore.getInstance("BKS");
            ks.load(null);

            char[] pw = password.toCharArray();

            final java.security.cert.X509Certificate certificate = makeCertificate(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic());
            final java.security.cert.X509Certificate[] certificateChain = { certificate };

            //save rootca like an alias
            ks.setKeyEntry("rootca", rsaKeyPair.getPrivate(), pw, certificateChain);

            File keyStoreFile= new File(fileName);
            final FileOutputStream fos = new FileOutputStream(
                    keyStoreFile);
            ks.store(fos, pw);
            fos.close();

            //to save into system properties
//            System.setProperty("javax.net.ssl.keyStore", keyStoreFile.getAbsolutePath());
//            System.setProperty("javax.net.ssl.keyStorePassword", password);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return fileName;
    }

    public static X509Certificate makeCertificate(PrivateKey issuerPrivateKey,
                                                  PublicKey subjectPublicKey) throws Exception {

        final int expiryDays = 2 * 365; //2 years
        final String CERTIFICATE_DN = "CN=, O=, L=, ST=, C="; //put your data here

        final Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, expiryDays);

        final org.bouncycastle.x509.X509V3CertificateGenerator certificateGenerator = new org.bouncycastle.x509.X509V3CertificateGenerator();

        certificateGenerator.setSerialNumber(java.math.BigInteger
                .valueOf(System.currentTimeMillis()));
        certificateGenerator.setIssuerDN(new X509Principal(CERTIFICATE_DN));

        certificateGenerator.setSubjectDN(new X509Principal(CERTIFICATE_DN));
        certificateGenerator.setPublicKey(subjectPublicKey);
        certificateGenerator.setNotBefore(new Date());
        certificateGenerator.setNotAfter(expiry.getTime());

        certificateGenerator.setSignatureAlgorithm("SHA256withRSA");

        return certificateGenerator.generate(issuerPrivateKey);
    }

    private AssetFileDescriptor getCertFileFromAssets(Context mainContext) {
        //Load certification file from assets
        AssetFileDescriptor certFile = null;
        AssetManager assetManager = mainContext.getAssets();
        try {
            String[] files = assetManager.list("certification");

            for (String file : files) {
                if (file.toUpperCase().contains("BKS"))
                    certFile = assetManager.openFd("certification/" + file);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return certFile;
    }

    private TrustManager getTrustManager() {

        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        return tm;
    }

    private TrustManager[] getTrustAllCerts() {

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
        return trustAllCerts;
    }
}
