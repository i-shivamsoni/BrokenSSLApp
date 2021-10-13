package com.example.brokensslapp;

import android.net.SSLCertificateSocketFactory;
import android.net.SSLSessionCache;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.SocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;

import java.io.IOException;

public class MainActivity extends AppCompatActivity {

    private Object MyWebViewClient = new MyWebViewClient();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        WebView myWebView = (WebView) findViewById(R.id.webview);
        myWebView.setWebViewClient((WebViewClient) MyWebViewClient);
        myWebView.loadUrl("https://www.google.com");
    }

    public void sendRequest2(View view) throws IOException {

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try  {
                    HostnameVerifier hostnameVerifier = new MyHostNameVerifier();
                    DefaultHttpClient client = new DefaultHttpClient();
                    SchemeRegistry registry = new SchemeRegistry();
                    SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();
                    socketFactory.setHostnameVerifier((X509HostnameVerifier) hostnameVerifier);
                    registry.register(new Scheme("https", socketFactory, 443));
                    SingleClientConnManager mgr = new SingleClientConnManager(client.getParams(), registry);
                    DefaultHttpClient httpClient = new DefaultHttpClient(mgr, client.getParams());
                    HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
                    final String url = "https://www.google.com/";
                    HttpPost httpPost = new HttpPost(url);
                    HttpResponse response = httpClient.execute(httpPost);
                    Log.d("Response", response.toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();

    }



    public void sendRequest(View view) throws IOException {
        /*
         send request to google.org
         - Vulnerable to "Broken SSL Trust Manager" as naive check implemented
            by MySSLSocketFactory()
         - Vulnerable to "HostnameVerifier Allowing All Hostnames" as connection evesdropping possible
            due to implementation ALLOW_ALL_HOSTNAME_VERIFIER
         */
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try  {
                    HostnameVerifier hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                    DefaultHttpClient client = new DefaultHttpClient();
                    SchemeRegistry registry = new SchemeRegistry();
                    SSLSocketFactory socketFactory = MySSLSocketFactory.getSocketFactory();
                    socketFactory.setHostnameVerifier((X509HostnameVerifier) hostnameVerifier);
                    registry.register(new Scheme("https", socketFactory, 443));
                    SingleClientConnManager mgr = new SingleClientConnManager(client.getParams(), registry);
                    DefaultHttpClient httpClient = new DefaultHttpClient(mgr, client.getParams());
                    HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
                    final String url = "https://www.google.org/";
                    HttpPost httpPost = new HttpPost(url);
                    HttpResponse response = httpClient.execute(httpPost);
                    Log.d("Response", response.toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();
    }

    public void sendRequest3(final View view) throws IOException {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try  {
                    DefaultHttpClient client = new DefaultHttpClient();
                    SchemeRegistry registry = new SchemeRegistry();
                    javax.net.ssl.SSLSocketFactory socketFactory = SSLCertificateSocketFactory.getInsecure(6000, new SSLSessionCache(view.getContext()));
                    registry.register(new Scheme("https", (SocketFactory) socketFactory, 443));
                    SingleClientConnManager mgr = new SingleClientConnManager(client.getParams(), registry);
                    DefaultHttpClient httpClient = new DefaultHttpClient(mgr, client.getParams());
                    final String url = "https://www.google.org/";
                    HttpPost httpPost = new HttpPost(url);
                    HttpResponse response = httpClient.execute(httpPost);
                    Log.d("Response", response.toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();
    }
}







