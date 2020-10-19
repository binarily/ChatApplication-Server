/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PublicKeyCrypto;

// import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.TreeMap;


public class AccessCerts {

    // private final String keyStore = "args[1].jks"; // keystore file should exist in the program folder of the application
    private final String keyStorePass = "password"; // password of keystore
    private final String keyPass = "password";

    private String user;
    private PublicKey my_public_key;
    private X509Certificate my_cert;
    private TreeMap<String, X509Certificate> all_certificates;
    private java.security.PrivateKey my_private_key;


    public AccessCerts(String user) throws Exception {

        try {
            // Alias
            this.user = user;
            final String keyStore = user + "KeyStore.jks";
            System.out.println("Working Directory = " + System.getProperty("user.dir"));
            System.out.println(keyStore);
            java.security.KeyStore ks = java.security.KeyStore.getInstance("JKS");
            java.io.FileInputStream ksfis = new java.io.FileInputStream(keyStore);
            java.io.BufferedInputStream ksbufin = new java.io.BufferedInputStream(ksfis);
            ks.load(ksbufin, keyStorePass.toCharArray());

            // Certificates in keystore
            this.all_certificates = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

            for (Enumeration<String> theAliases = ks.aliases(); theAliases.hasMoreElements(); ) {
                String alias = (String) theAliases.nextElement();
                X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
                all_certificates.put(alias, certificate);
            }

            // System.out.println(all_certificates);


            this.my_cert = (X509Certificate) ks.getCertificate(user);

            this.my_public_key = my_cert.getPublicKey();

            this.my_private_key = (java.security.PrivateKey) ks.getKey(user, keyPass.toCharArray());
        } catch (Exception e) {
            System.out.println("Certification read fails: " + e.getMessage());
        }


    }


    // getters

    public String getUser() {

        return user;

    }

    public PublicKey getMyPublicKey() {

        return my_public_key;

    }

    public PrivateKey getMyPrivateKey() {

        return my_private_key;

    }

    public TreeMap<String, X509Certificate> getAllCertificates() {

        return all_certificates;

    }

    public X509Certificate getMyCertificate() {

        return my_cert;

    }


}
