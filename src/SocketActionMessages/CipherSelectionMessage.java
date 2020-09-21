/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SocketActionMessages;

import java.io.Serializable;

public class CipherSelectionMessage implements Serializable
{
    protected static final long serialVersionUID = 1112122201L;

    private int selectedCipher;

    private byte[] mac;



    // constructor

    public CipherSelectionMessage(int selectedCipher, byte[] mac) {

        this.selectedCipher = selectedCipher;

        this.mac = mac;

    }

     

    // getters

    public int getSelectedCipher() {

        return selectedCipher;

    }

    public byte[] getMac() {

        return mac;

    }
}
