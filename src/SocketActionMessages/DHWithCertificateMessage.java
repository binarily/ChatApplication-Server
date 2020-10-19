/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SocketActionMessages;

import java.io.Serializable;

public class DHWithCertificateMessage implements Serializable {
    protected static final long serialVersionUID = 1112122202L;

    private byte[] certificate;

    private byte[] diffieHellman;

    // constructor

    public DHWithCertificateMessage(byte[] certificate, byte[] diffieHellman) {

        this.certificate = certificate;

        this.diffieHellman = diffieHellman;

    }

    // getters
    public byte[] getCertificate() {
        return certificate;
    }

    public byte[] getDiffieHellman() {
        return diffieHellman;
    }

    public long getDHFromResponse() {
        //TODO
        //Check certificate with CA
        //If it works: decode with public key
        return 0l;
    }

    public static DHWithCertificateMessage createEncrypted(byte[] certificate, long dh) {
        //TODO
        //Sign dh with private key
        //Add certificate with end
        return new DHWithCertificateMessage(new byte[]{}, new byte[]{});
    }
}
