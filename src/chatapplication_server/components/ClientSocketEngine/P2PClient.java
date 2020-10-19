/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import SocketActionMessages.ChatMessage;
import SocketActionMessages.DHWithCertificateMessage;
import chatapplication_server.components.ConfigManager;
import chatapplication_server.components.base.Constants;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.util.TreeMap;
import java.lang.String;
import java.nio.charset.StandardCharsets;

import PublicKeyCrypto.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
    JButton Send, stopStart;
    JButton connectStop;

    /**
     * Client Socket and output stream...
     */
    Socket socket = null;
    ObjectOutputStream sOutput;

    private ListenFromClient clientServer;

    /**
     * Flag indicating whether the Socket Server is running at one of the Clients...
     */
    boolean isRunning;

    /**
     * Flag indicating whether another client is connected to the Socket Server...
     */
    boolean isConnected;


    private String username;
    private PublicKey public_key,server_public_key;
    private X509Certificate cert;
    private TreeMap<String, X509Certificate> all_certificates;
    private PrivateKey private_key;

    P2PClient( String username) {

        super("P2P Client Chat");

        this.username = username;
        try 
        {
            AccessCerts key_store = new AccessCerts(username);
            this.cert = key_store.getMyCertificate();
            this.all_certificates = key_store.getAllCertificates();
            this.private_key = key_store.getMyPrivateKey();
            this.server_public_key = all_certificates.get("server").getPublicKey();
            System.out.println("\tkey " + server_public_key.toString());

        }
        catch ( Exception e )
        {
            display( "Error connecting to the server:" + e.getMessage() + "\n" );
            ClientSocketGUI.getInstance().loginFailed();
        }


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
        stopStart = new JButton("Start");
        stopStart.addActionListener(this);

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

        connectStop = new JButton("Connect");
        connectStop.addActionListener(this);

        Send = new JButton("Send");
        Send.addActionListener(this);
        Send.setVisible(false);
        JPanel southPanel = new JPanel();
        southPanel.add(connectStop);
        southPanel.add(Send);
        southPanel.add(stopStart);
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

        isRunning = false;
        isConnected = false;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();

        if (o == connectStop) {
            if (connectStop.getText().equals("Connect") && isConnected == false) {
                if (tfPort.getText().equals(ConfigManager.getInstance().getValue("Server.PortNumber"))) {
                    display("Cannot give the same port number as the Chat Application Server - Please give the port number of the peer client to communicate!\n");
                    return;
                }

                /** Connect to the Socket Server instantiated by the other client... */
                this.connect();
            } else if (connectStop.getText().equals("Disconnect") && isConnected == true) {
                this.disconnect();
            }
        } else if (o == Send) {
            /** Try to send the message to the other communicating party, if we have been connected... */
            if (isConnected == true) {
                this.send(tf.getText());
            }
        } else if (o == stopStart) {
            if (stopStart.getText().equals("Start") && isRunning == false) {
                clientServer = new ListenFromClient();
                clientServer.start();
                isRunning = true;
                stopStart.setText("Stop");
            } else if (stopStart.getText().equals("Stop") && isRunning == true) {
                clientServer.shutDown();
                clientServer.stop();
                isRunning = false;
                stopStart.setText("Start");
            }
        }
    }

    public void display(String str) {
        ta.append(str + "\n");
        ta.setCaretPosition(ta.getText().length() - 1);
    }

    /**
     * Method that is invoked when a client wants to connect to the Socket Server spawn from another client in order to initiate their P2P communication.
     *
     * @return TRUE if the connection was successful; FALSE otherwise
     */
    public boolean connect() {
        /* Try to connect to the Socket Server... */
        try {
            if (isConnected == false) {
                socket = new Socket(tfServer.getText(), Integer.parseInt(tfPort.getText()));

                sOutput = new ObjectOutputStream(socket.getOutputStream());
                isConnected = true;
                Send.setVisible(true);
                connectStop.setText("Disconnect");

                return true;
            }
        } catch (IOException eIO) {
            display("The Socket Server from the other side has not been fired up!!\nException creating new Input/output Streams: " + eIO.getMessage() + "\n");
            isConnected = false;
            Send.setVisible(false);
            connectStop.setText("Connect");
            return false;
        }
        // if it failed not much I can so
        catch (Exception ec) {
            display("Error connecting to server:" + ec.getMessage() + "\n");
            isConnected = false;
            Send.setVisible(false);
            connectStop.setText("Connect");
            return false;
        }

        return true;
    }

    /**
     * Method that is invoked when we want do disconnect from a Socket Server (spawn by another client); this, basically, reflects the stopping of a P2P communication
     *
     * @return TRUE if the disconnect was successful; FALSE, otherwise
     */
    public boolean disconnect() {
        /** Disconnect from the Socket Server that we are connected... */
        try {
            if (isConnected == true) {
                /** First, close the output stream... */
                sOutput.close();

                /** Then, close the socket... */
                socket.close();

                /** Re-initialize the parameters... */
                isConnected = false;
                Send.setVisible(false);
                connectStop.setText("Connect");

                return true;
            }
        } catch (IOException ioe) {
            display("Error closing the socket and output stream: " + ioe.getMessage() + "\n");

            /** Re-initialize the parameters... */
            isConnected = false;
            Send.setVisible(false);
            connectStop.setText("Connect");
            return false;
        }

        return true;
    }

    public void initializeCiphers() {
        if (KEY == -1) {
            throw new IllegalArgumentException("Key cannot be -1");
        }
        try {
            //Hash key value
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] keyHash = md.digest(String.valueOf(KEY).getBytes(StandardCharsets.UTF_8));
            SecretKeySpec keyUsed = new SecretKeySpec(Arrays.copyOfRange(keyHash, 0, 16), Constants.KEY_ALGORITHM);

            //Establish used ciphers
            encryptCipher = Cipher.getInstance(Constants.ALGORITHM);
            encryptCipher.init(Cipher.ENCRYPT_MODE, keyUsed, Constants.INITIALIZATION_VECTOR);
            decryptCipher = Cipher.getInstance(Constants.ALGORITHM);
            decryptCipher.init(Cipher.DECRYPT_MODE, keyUsed, Constants.INITIALIZATION_VECTOR);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

    public boolean send(String str) {
        // to write on the socket
        try {
            //send key request
            if (KEY == -1) {
                Long response = Constants.G ^ A % Constants.P;
                String responseToEncrypt = username + "," + response;
                public_key = all_certificates.get(str).getPublicKey();
                Cipher dhEncryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                dhEncryptCipher.init(Cipher.PUBLIC_KEY, public_key);
                byte[] encryptedResponse = dhEncryptCipher.doFinal(responseToEncrypt.getBytes(StandardCharsets.UTF_8));
                sOutput.writeObject(encryptedResponse);
                requestSent = true;
            } else {
                //encrypt here
                try {
                    ChatMessage message = new ChatMessage(str.length(), str);
                    byte[] plainText = message.toP2PString().getBytes(StandardCharsets.UTF_8);
                    byte[] cipherText = encryptCipher.doFinal(plainText);
                    sOutput.writeObject(cipherText);
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    display("Exception encrypting: " + e);
                }
                display("You: " + str);
            }
        } catch (IOException ex) {
            display("Exception creating new Input/output Streams: " + ex);
            this.disconnect();
            return false;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException ex) {
            display("Exception creating crypto: " + ex);
            this.disconnect();
            return false;
        }

        return true;
    }

    private class ListenFromClient extends Thread {
        ServerSocket serverSocket;
        Socket socket;
        ObjectInputStream sInput = null;
        boolean clientConnect;

        public ListenFromClient() {
            try {
                // the socket used by the server
                serverSocket = new ServerSocket(Integer.parseInt(tfsPort.getText()));
                ta.append("Server is listening on port:" + tfsPort.getText() + "\n");
                ta.setCaretPosition(ta.getText().length() - 1);
                clientConnect = false;
                keepGoing = true;
            } catch (IOException ioe) {
                System.out.println("[P2PClient]:: Error firing up Socket Server " + ioe.getMessage());
            }
        }

        @Override
        public void run() {
            // infinite loop to wait for messages
            while (keepGoing) {
                /** Wait only when there are no connections... */
                try {
                    if (!clientConnect) {
                        socket = serverSocket.accept();    // accept connection
                        sInput = new ObjectInputStream(socket.getInputStream());
                        clientConnect = true;
                    }
                } catch (IOException ex) {
                    display("The Socket Server was closed: " + ex.getMessage());
                }

                try {
                    // format message saying we are waiting
                    //respond to exchanging keys here
                    if (KEY == -1) {
                        byte[] response = (byte[]) sInput.readObject();
                        Cipher dhDecryptionCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                        dhDecryptionCipher.init(Cipher.PRIVATE_KEY, private_key);
                        byte[] decryptedResponse = dhDecryptionCipher.doFinal(response);
                        String responseString = new String(decryptedResponse);
                        Long gB = Long.valueOf(responseString.split(",", 2)[1]);
                        KEY = gB ^ A % Constants.P;
                        initializeCiphers();
                        if (!requestSent) {
                            String receiver = responseString.split(",", 2)[0];
                            Long responseB = Constants.G ^ A % Constants.P;
                            String responseStr = receiver + "," + responseB;
                            public_key = all_certificates.get(receiver).getPublicKey();
                            Cipher dhEncryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                            dhEncryptCipher.init(Cipher.PUBLIC_KEY, public_key);
                            byte[] encryptedResponse = dhEncryptCipher.doFinal(responseStr.getBytes(StandardCharsets.UTF_8));
                            sOutput.writeObject(encryptedResponse);
                            requestSent = true;
                        }
                    } else {
                        //decrypt here
                        byte[] encryptedMessage = (byte[]) sInput.readObject();
                        byte[] plainText = decryptCipher.doFinal(encryptedMessage);
                        String decryptedMessage = new String(plainText);
                        ChatMessage cm = new ChatMessage(Integer.parseInt(decryptedMessage.substring(0, 1)), decryptedMessage.substring(1));

                        String msg = cm.getStringMessage();
                        display(socket.getInetAddress() + ": " + socket.getPort() + ": " + msg);
                    }
                } catch (IOException ex) {
                    display("Could not ready correctly the messages from the connected client: " + ex.getMessage());
                    clientConnect = false;
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(P2PClient.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                    display("Exception decrypting: " + e);
                }
            }
        }

        public void shutDown() {
            try {
                keepGoing = false;
                if (socket != null) {
                    sInput.close();
                    socket.close();
                }

                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException ioe) {
                System.out.println("[P2PClient]:: Error closing Socket Server " + ioe.getMessage());
            }
        }
    }
}