/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PublicKeyCrypto;

// import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Enumeration;

import java.io.IOException;
import java.security.KeyStoreException;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

// import java.util.HashMap;
import java.util.TreeMap;
import java.lang.String; 


public class AccessCerts {

  // private final String keyStore = "args[1].jks"; // keystore file should exist in the program folder of the application
  private final String keyStorePass = "asda123"; // password of keystore
  private final String keyPass = "asda123";

  private String user;
  private PublicKey my_public_key;
  private X509Certificate my_cert;
  private TreeMap<String, X509Certificate> all_certificates;
  private java.security.PrivateKey my_private_key;


  public AccessCerts( String user) throws Exception{

    try
    {
        // Alias
        this.user = user;
        final String keyStore = user + "KeyStore.jks";
        System.out.println("Working Directory = " + System.getProperty("user.dir"));
        System.out.println(keyStore);
        java.security.KeyStore ks = java.security.KeyStore.getInstance( "JKS" );
        java.io.FileInputStream ksfis = new java.io.FileInputStream( keyStore );
        java.io.BufferedInputStream ksbufin = new java.io.BufferedInputStream( ksfis );
        ks.load( ksbufin, keyStorePass.toCharArray() );

        // Certificates in keystore
        this.all_certificates = new TreeMap<String,X509Certificate>(String.CASE_INSENSITIVE_ORDER);

        for( java.util.Enumeration theAliases = ks.aliases(); theAliases.hasMoreElements(); ) {
            String alias = (String) theAliases.nextElement();
            X509Certificate certificate = (X509Certificate) ks.getCertificate( alias );
            all_certificates.put(alias, certificate);
        }

        // System.out.println(all_certificates);


        this.my_cert = (X509Certificate) ks.getCertificate(user);

        this.my_public_key = my_cert.getPublicKey();

        this.my_private_key = (java.security.PrivateKey) ks.getKey( user , keyPass.toCharArray() );
    }
    catch (Exception e) {
        return ;
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

  public TreeMap<String, X509Certificate> getAllCertificates () {

      return all_certificates;

  }

  public X509Certificate getMyCertificate() {

      return my_cert;

  }



}
