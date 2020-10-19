/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import chatapplication_server.ComponentManager;
import java.io.IOException;
import java.io.ObjectInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 *
 * @author atgianne
 */
public class ListenFromServer extends Thread 
{

    Cipher cipher = null;

    public ListenFromServer(Cipher cipher) {
        this.cipher = cipher;
    }

    public void run()
    {
        while(true) {
                ObjectInputStream sInput = ClientEngine.getInstance().getStreamReader();
                
                synchronized( sInput )
                {
                    try
                    {

                        //decrypt here
                        System.out.println("AKOUUUUoo  ");
                        byte[] encryptedMessage = (byte[]) sInput.readObject();
                        byte[] plainText = cipher.doFinal(encryptedMessage);
                        String msg = new String(plainText);
                        System.out.println("AKOUUUUoo  ");
                        
                        if(msg.contains( "#" ))
                        {
                            ClientSocketGUI.getInstance().appendPrivateChat(msg + "\n");
                        }
                        else
                        {
                            ClientSocketGUI.getInstance().append(msg + "\n");
                        }
                    }
                    catch(IOException e) 
                    {
                        ClientSocketGUI.getInstance().append( "Server has closed the connection: " + e.getMessage() +"\n" );
                        ComponentManager.getInstance().fatalException(e);
                    }
                    catch(ClassNotFoundException cfe) 
                    {
                        ClientSocketGUI.getInstance().append( "Server has closed the connection: " + cfe.getMessage() );
                        ComponentManager.getInstance().fatalException(cfe);
                    }
                    catch (BadPaddingException | IllegalBlockSizeException e) {
                        ClientSocketGUI.getInstance().append("Decryption failed: " + e.getMessage());
                        ComponentManager.getInstance().fatalException(e);
                    }
                }
        }
    }
}
