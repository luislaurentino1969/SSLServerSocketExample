package com.example.sslserversocketexample;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * By: Luis Laurentino
 * Date: 03/22/2019
 *
 * HTTPS Server
 * Start and Listen a local https url
 * create automatically own BKS file
 */
public class HTTPSServer extends Thread {

    private static final String TAG = HTTPSServer.class.getSimpleName();
    private static boolean isServerRunning;

    private final String PASSPHRASE = "passphrase";

    private int _port;

    private String _securityFileName;

    private Context _mainContext;
    private SSLServerSocket _sslServerSocket;
    private Handler _handler;

    HTTPSServer(Context mainContext, Integer portNumber) {

        if (mainContext == null || portNumber == null || portNumber < 1) {
            throw new Error("HTTPSServer Class Invalid parameters.");
        }

        _mainContext = mainContext;
        _port = portNumber;
        isServerRunning = false;
        _handler = new Handler(Looper.getMainLooper());

    }

    @Override
    public void interrupt() {
        try {
            isServerRunning = false;
            _sslServerSocket.close();
            System.out.println("SSL server STOPPED");
        } catch (IOException e) {
            Log.e(TAG, "Error stopping server ====> " + e.getMessage());
            e.printStackTrace();
        }
        super.interrupt();
    }

    @Override
    public void run() {

        // Create a new BKS file
        _securityFileName = HTTPUtils.createBKSFile(_mainContext, PASSPHRASE);

        // Get the context base on security file created
        SSLContext sslContext = this.getContext();

        try {
            // get server socket factory base on context created
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create server socket
            _sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(_port);
            _sslServerSocket.setUseClientMode(false);
            _sslServerSocket.setNeedClientAuth(true);
            _sslServerSocket.setWantClientAuth(true);
            _sslServerSocket.setEnableSessionCreation(true);

            // Start server thread
            System.out.println("SSL server listen on port ====> " + _port);
            showUIMessage(String.format("\t\tPort number ====> %s", _port));
            isServerRunning = true;
            new ServerThread().run();

        } catch (Exception ex) {
            Log.e(TAG, "Error starting server ====> " + ex.getMessage());
            ex.printStackTrace();
            isServerRunning = false;
        }
    }

    /**
     * Send and Show message to Main Activity
     * @required message
     */
    private void showUIMessage(String message) {
        _handler.post(() -> {
            EditText _tvMessage = ((MainActivity) _mainContext).findViewById(R.id._tvMessage);
            _tvMessage.setText(String.format("%s%s\r\n", _tvMessage.getText(), message));
        });
    }

    /**
     * Create a new SSLContext to start the server
     * using the BKS file created
     *
     * @return SSLContext
     */
    private synchronized SSLContext getContext() {

        try {
            java.security.Security.setProperty("jdk.tls.disabledAlgorithms", "");
            java.security.Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] passphrase = PASSPHRASE.toCharArray();
            try {
                InputStream keyFileStream = new FileInputStream(_securityFileName);
                ks.load(keyFileStream, passphrase);
            } catch (CertificateException | IOException ex) {
                ex.printStackTrace();
                Log.e(TAG, ex.getMessage());
                throw new Error("Unexpected exception", ex);
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(ks, passphrase);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(ks);

            SSLContext sslCtx = SSLContext.getInstance("TLS");

            sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslCtx;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyManagementException ex) {
            Log.e(TAG, ex.getMessage());
            throw new Error("Unexpected exception", ex);
        }
    }

    /**
     * Thread listening the socket server
     */
    class ServerThread extends Thread {
        @Override
        public void run() {
            try {
                while (isServerRunning && !this.isInterrupted()) {

                    SSLSocket sslSocket = (SSLSocket) _sslServerSocket.accept();

                    // Start the client thread
                    new ClientThread(sslSocket).run();
                }
            } catch (Exception ex) {
                Log.e(TAG, "Error listening server ====> " + ex.getMessage());
                ex.printStackTrace();
            } finally {
                isServerRunning = false;
            }
        }
    }

    /**
     * Thread handling the socket from client
     * process request and send response back
     *
     * @required SSLSocket client connection
     */
    class ClientThread extends Thread {
        final String TAG = ClientThread.class.getSimpleName();
        private SSLSocket sslSocket;

        ClientThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        @Override
        public void run() {
            DataOutputStream outputWriter = null;
            try {

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();
                Log.i(TAG, "Session created " + sslSession.getCreationTime());

                // Send message to UI
                showUIMessage("Client Session created.");

                // Start handshake
                sslSocket.startHandshake();

                outputWriter = new DataOutputStream(sslSocket.getOutputStream());
                OutputStream outputStream = sslSocket.getOutputStream();

                // load request
                String line = getRequestHeader(new BufferedReader(new InputStreamReader(sslSocket.getInputStream())));
                showUIMessage("Received Client request.");

                String method = line.toUpperCase().substring(0, line.contains(" ") ? line.indexOf(" ") : line.length()).trim();

                // process request
                switch (method) {
                    case "GET":
                        Log.i(TAG, "run: GET =======> " + line);
                        showUIMessage("Processing GET request.");
                        //TODO implement GET handler
                        break;
                    case "POST":
                        Log.i(TAG, "run: POST =======> " + line);
                        showUIMessage("Processing POS request.");
                        //TODO implement POST handler
                        break;
                    case "PUT":
                        Log.i(TAG, "run: PUT =======> " + line);
                        showUIMessage("Processing PUT request.");
                        //TODO implement PUT handler
                        break;
                    default:
                        break;
                }

                String response = line.replace(method, "");

                // Write response
                int responseSize = response.length();

                outputWriter.writeBytes("HTTP/1.1 200 OK\r\n");
                outputWriter.writeBytes("Content-Length: " + responseSize + "\r\n");
                outputWriter.writeBytes("Content-Type: text/plain;\r\n\r\n");
                outputWriter.flush();

                if (responseSize > 0) {
                    outputStream.write((response + "\r\n\r\n").getBytes());
                    outputStream.flush();
                }
                showUIMessage("Sent response to Client.");

            } catch (Exception ex) {

                Log.e(TAG, ex.getMessage());
                ex.printStackTrace();

                try {
                    if (!(ex instanceof SocketException)) {
                        if (outputWriter != null) {
                            outputWriter.writeBytes("HTTP/1.0 400 SOCKET ERROR\r\n");
                            outputWriter.writeBytes("Content-Type: text/plain\r\n");
                            outputWriter.flush();
                        }
                    }

                } catch (IOException ie) {
                    ie.printStackTrace();
                }

            } finally {

                try {
                    sslSocket.close();

                } catch (IOException e) {
                    Log.e(TAG, e.getMessage());
                    e.printStackTrace();
                }
            }
        }

        /**
         * Load request HEADER
         *
         * @return string request
         * @required bufferedReader
         */
        private String getRequestHeader(BufferedReader bufferedReader) {
            String line;
            StringBuilder result = new StringBuilder();
            try {
                while ((line = bufferedReader.readLine()) != null) {
                    result.append(line);
                    if (line.trim().isEmpty()) {
                        break;
                    }
                }
            } catch (IOException ie) {

                Log.e(TAG, "Error preparing HEADER ====> " + ie.getMessage());
                ie.printStackTrace();
            }
            return result.toString();
        }
    }
}
