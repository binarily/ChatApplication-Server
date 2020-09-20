/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import SocketActionMessages.ChatMessage;
import chatapplication_server.components.ConfigManager;
import chatapplication_server.components.base.Constants;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author atgianne
 */
public class P2PClient extends JFrame implements ActionListener {

    private Long KEY = -1l;
    private long A = Math.floorMod(new Random().nextLong(), Constants.Q) + 1;
    private Cipher decryptCipher = null;
    private Cipher encryptCipher = null;
    private boolean requestSent = false;

    private String host;
    private String port;
    private final JTextField tfServer;
    private final JTextField tfPort;
    private final JTextField tfsPort;
    private final JLabel label;
    private final JTextField tf;
    private final JTextArea ta;
    protected boolean keepGoing;
    JButton send, start;

    P2PClient() {
        super("P2P Client Chat");
        host = ConfigManager.getInstance().getValue("Server.Address");
        port = ConfigManager.getInstance().getValue("Server.PortNumber");

        // The NorthPanel with:
        JPanel northPanel = new JPanel(new GridLayout(3, 1));
        // the server name anmd the port number
        JPanel serverAndPort = new JPanel(new GridLayout(1, 5, 1, 3));
        // the two JTextField with default value for server address and port number
        tfServer = new JTextField(host);
        tfPort = new JTextField("" + port);
        tfPort.setHorizontalAlignment(SwingConstants.RIGHT);

        tfsPort = new JTextField(5);
        tfsPort.setHorizontalAlignment(SwingConstants.RIGHT);
        start = new JButton("Start");
        start.addActionListener(this);

        serverAndPort.add(new JLabel("Receiver's Port No:  "));
        serverAndPort.add(tfPort);
        serverAndPort.add(new JLabel("Receiver's IP Add:  "));
        serverAndPort.add(tfServer);
        serverAndPort.add(new JLabel(""));
        // adds the Server an port field to the GUI
        northPanel.add(serverAndPort);

        // the Label and the TextField
        label = new JLabel("Enter message below", SwingConstants.LEFT);
        northPanel.add(label);
        tf = new JTextField();
        tf.setBackground(Color.WHITE);
        northPanel.add(tf);
        add(northPanel, BorderLayout.NORTH);

        // The CenterPanel which is the chat room
        ta = new JTextArea(" ", 80, 80);
        JPanel centerPanel = new JPanel(new GridLayout(1, 1));
        centerPanel.add(new JScrollPane(ta));
        ta.setEditable(false);

//        ta2 = new JTextArea(80,80);
//        ta2.setEditable(false);
//        centerPanel.add(new JScrollPane(ta2));   
        add(centerPanel, BorderLayout.CENTER);


        send = new JButton("Send");
        send.addActionListener(this);
        JPanel southPanel = new JPanel();
        southPanel.add(send);
        southPanel.add(start);
        JLabel lbl = new JLabel("Sender's Port No:");
        southPanel.add(lbl);
        tfsPort.setText("0");
        southPanel.add(tfsPort);
        add(southPanel, BorderLayout.SOUTH);

        this.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

//        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(600, 600);
        setVisible(true);
        tf.requestFocus();
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();
        if (o == send) {
            if (tfPort.getText().equals(ConfigManager.getInstance().getValue("Server.PortNumber"))) {
                display("Cannot give the same port number as the Chat Application Server - Please give the port number of the peer client to communicate!\n");
                return;
            }
            this.send(tf.getText());
        }
        if (o == start) {
            new ListenFromClient().start();
        }
    }

    public void display(String str) {
        ta.append(str + "\n");
        ta.setCaretPosition(ta.getText().length() - 1);
    }

    public void initializeCiphers() {
        if(KEY == -1) {
            throw new IllegalArgumentException("Key cannot be -1");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] keyHash = md.digest(String.valueOf(KEY).getBytes(StandardCharsets.UTF_8));
            SecretKeySpec keyUsed = new SecretKeySpec(Arrays.copyOfRange(keyHash, 0, 16), Constants.KEY_ALGORITHM);

            encryptCipher = Cipher.getInstance(Constants.ALGORITHM);
            encryptCipher.init(Cipher.ENCRYPT_MODE, keyUsed, Constants.INITIALIZATION_VECTOR);
            decryptCipher = Cipher.getInstance(Constants.ALGORITHM);
            decryptCipher.init(Cipher.DECRYPT_MODE, keyUsed, Constants.INITIALIZATION_VECTOR);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

    public boolean send(String str) {
        Socket socket;
        ObjectOutputStream sOutput;
        // to write on the socket
        // try to connect to the server
        try {
            socket = new Socket(tfServer.getText(), Integer.parseInt(tfPort.getText()));
        }
        // if it failed not much I can so
        catch (Exception ec) {
            display("Error connectiong to server:" + ec.getMessage() + "\n");
            return false;
        }

        /* Creating both Data Stream */
        try {
//			sInput  = new ObjectInputStream(socket.getInputStream());
            sOutput = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException eIO) {
            display("Exception creating new Input/output Streams: " + eIO);
            return false;
        }

        try {
            //TODO: send key request
            if (KEY == -1) {
                Long response = Constants.G ^ A % Constants.P;
                //TODO: make response hashed
                sOutput.writeObject(response);
                requestSent = true;
            } else {
                //TODO: encrypt here
                try {
                    ChatMessage message = new ChatMessage(str.length(), str);
                    byte[] plainText = message.toString().getBytes(StandardCharsets.UTF_8);
                    byte[] cipherText = encryptCipher.doFinal(plainText);
                    sOutput.writeObject(cipherText);
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    display("Exception encrypting: " + e);
                }
                display("You: " + str);
                sOutput.close();
                socket.close();
            }
        } catch (IOException ex) {
            display("Exception creating new Input/output Streams: " + ex);
        }

        return true;
    }

    public boolean sendDiffieHellman(Long result) {
        Socket socket;
        ObjectOutputStream sOutput;
        // to write on the socket
        // try to connect to the server
        try {
            socket = new Socket(tfServer.getText(), Integer.parseInt(tfPort.getText()));
        }
        // if it failed not much I can so
        catch (Exception ec) {
            display("Error connectiong to server:" + ec.getMessage() + "\n");
            return false;
        }

        /* Creating both Data Stream */
        try {
//			sInput  = new ObjectInputStream(socket.getInputStream());
            sOutput = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException eIO) {
            display("Exception creating new Input/output Streams: " + eIO);
            return false;
        }

        try {
            sOutput.writeObject(result);
        } catch (IOException ex) {
            display("Exception creating new Input/output Streams: " + ex);
        }

        return true;
    }

    private class ListenFromClient extends Thread {
        public ListenFromClient() {
            keepGoing = true;
        }

        @Override
        public void run() {
            try {
                // the socket used by the server
                ServerSocket serverSocket = new ServerSocket(Integer.parseInt(tfsPort.getText()));
                //display("Server is listening on port:"+tfsPort.getText());
                ta.append("Server is listening on port:" + tfsPort.getText() + "\n");
                ta.setCaretPosition(ta.getText().length() - 1);

                // infinite loop to wait for connections
                while (keepGoing) {
                    // format message saying we are waiting

                    Socket socket = serverSocket.accept();    // accept connection

                    ObjectInputStream sInput = null;        // to write on the socket

                    /* Creating both Data Stream */
                    try {
                        sInput = new ObjectInputStream(socket.getInputStream());
                    } catch (IOException eIO) {
                        display("Exception creating new Input/output Streams: " + eIO);
                    }

                    try {
                        //TODO: respond to exchanging keys here
                        if (KEY == -1) {
                            //TODO: unhash
                            Long gB = (Long) sInput.readObject();
                            KEY = gB ^ A % Constants.P;
                            initializeCiphers();
                            if (!requestSent) {
                                //TODO: KEY should get hashed somewhat for better key
                                Long response = Constants.G ^ A % Constants.P;
                                sendDiffieHellman(response);
                                requestSent = true;
                            }
                            //TODO: hash
                        } else {
                            //TODO: decrypt here
                            byte[] encryptedMessage = (byte[]) sInput.readObject();
                            byte[] plainText = decryptCipher.doFinal(encryptedMessage);
                            String decryptedMessage = new String(plainText);
                            ChatMessage cm = new ChatMessage(Integer.parseInt(decryptedMessage.substring(0, 1)), decryptedMessage.substring(1));

                            String msg = cm.getMessage();
                            System.out.println("Msg:" + msg);
                            display(socket.getInetAddress() + ": " + socket.getPort() + ": " + msg);
                        }
                        sInput.close();
                        socket.close();
                    } catch (IOException ex) {
                        display("Exception creating new Input/output Streams: " + ex);
                    } catch (ClassNotFoundException ex) {
                        Logger.getLogger(P2PClient.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException | IllegalBlockSizeException e) {
                        display("Exception decrypting: " + e);
                    }

                }
            }
            // something went bad
            catch (IOException e) {
//            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
//			display(msg);
            }
        }
    }
}
