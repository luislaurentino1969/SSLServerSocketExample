package com.example.sslserversocketexample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends AppCompatActivity {

    EditText _tvMessage;
    HTTPSServer server;
    int portNumber = 8181;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnStart = findViewById(R.id._btnStartServer);
        btnStart.setText("START SERVER");
        _tvMessage = findViewById(R.id._tvMessage);
        _tvMessage.setText("");
        _tvMessage.setInputType(InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        _tvMessage.setSingleLine(false);
        _tvMessage.setFocusable(false);

        btnStart.setOnClickListener((v)->{
            try {
                if (server != null) {
                    _tvMessage.setText(String.format("%sServer already running.\r\n", _tvMessage.getText()));
                } else {
                    server = new HTTPSServer(this, portNumber);
                    server.start();
                    _tvMessage.setText(String.format("%sServer started and listening\r\n", _tvMessage.getText()));
                }
            } catch (Exception e) {
                _tvMessage.setText(String.format("%sError:\r\n%s", _tvMessage.getText(), e.getMessage()));
                e.printStackTrace();
            }
        });

    }

}
