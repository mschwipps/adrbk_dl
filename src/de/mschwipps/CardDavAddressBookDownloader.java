package de.mschwipps;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Iterator;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.StrictHostnameVerifier;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.QName;
import org.dom4j.io.SAXReader;

/**
 * Tool zum Download vollständiger Adressbücher von einem CardDav-Server.
 */
public final class CardDavAddressBookDownloader {

    /* Constructor wird nicht benötigt */
    private CardDavAddressBookDownloader(){
    }

    /**
     * Startroutine
     * 
     * 
     * @param argv argv[0] - Dateiname des Property-Files.
     */
    public static void main(String argv[]) {
        try {
            if(null == argv || 0 >= argv.length)
                return;

            Properties p = new Properties();
            p.load(new FileInputStream(argv[0]));

            if(init(p)) {
                String adrbuch_path = p.getProperty("path");
                writeVCards(adrbuch_path);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    private static HttpClient client;
    private static HttpHost targetHost;

    /**
     * init liest die Verbindungs-Einstellungen aus dem Properties-File
     *
     * @return true - wenn die Verbindung erfolgreich aufgebaut werden kann
     */
    private static boolean init(Properties props) throws IOException, KeyManagementException,
        NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CertificateException {

        String host = props.getProperty("host");
        if(null == host || "".equals(host)) {
            System.err.println("kein Host festgelegt");
            return false;
        }

        String path = props.getProperty("path");
        if(null == path || "".equals(path)) {
            System.err.println("kein Pfad festgelegt");
            return false;
        }

        String port = props.getProperty("port", "443");
        int portInt = 443;
        if(null == port || "".equals(port))
            System.err.println("kein Port festgelegt");
        else {
            try {
                portInt = Integer.valueOf(port);
            } catch(NumberFormatException ex) {
                System.err.println("kein gültiger Port festgelegt: " + port);
                return false;
            }
        }

        String user = props.getProperty("user");
        if(null == user || "".equals(user)) {
            System.err.println("kein User festgelegt");
            return false;
        }

        String pwd = props.getProperty("password");
        if(null == pwd || "".equals(pwd)) {
            System.err.println("kein Passwort festgelegt");
            return false;
        }

        final SSLConnectionSocketFactory factory = initSSL(props.getProperty("keystore"));

        host = host.endsWith("/") ? host.substring(0, host.length() - 1) : host;
        path = !path.endsWith("/") ? path + "/" : path;
        if(!path.startsWith("/"))
            path = "/" + path;

        Credentials credentials = new UsernamePasswordCredentials(user, pwd);
        CredentialsProvider credProv = new BasicCredentialsProvider();
        credProv.setCredentials(AuthScope.ANY, credentials);

        HttpClientBuilder builder = HttpClientBuilder.create();
        builder.setDefaultCredentialsProvider(credProv);

        RegistryBuilder<ConnectionSocketFactory> r1 = RegistryBuilder
            .<ConnectionSocketFactory> create().register("http",
                PlainConnectionSocketFactory.getSocketFactory());
        if(null != factory)
            r1 = r1.register("https", factory);
        Registry<ConnectionSocketFactory> r = r1.build();
        HttpClientConnectionManager conMan = new BasicHttpClientConnectionManager(r);
        builder.setConnectionManager(conMan);

        client = builder.build();

        String protocol = props.getProperty("protocol", "https");

        targetHost = new HttpHost(host, portInt, protocol);
        return true;
    }

    /**
     * writeVCards liefert die VCards auf stdout. 
     * 
     * @param adrbPath
     */
    private static void writeVCards(String adrbPath) throws IOException, IllegalStateException,
        DocumentException {
        ReportMethod report = new ReportMethod(adrbPath);
        report.setHeader("Content-Type", "text/xml; charset=\"utf-8\"");
        report.setRequestBody("<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
            + "<C:addressbook-query xmlns:D=\"DAV:\""
            + "xmlns:C=\"urn:ietf:params:xml:ns:carddav\">" + "<D:prop>" + "<C:address-data/>"
            + "</D:prop>" + "</C:addressbook-query>");
        HttpResponse httpResponse = client.execute(targetHost, report);

        int code = httpResponse.getStatusLine().getStatusCode();
        if(code < 200 || code >= 300) {
            System.err.println("Error: " + code + " "
                + httpResponse.getStatusLine().getReasonPhrase());
            return;
        }

        SAXReader r = new SAXReader();
        Document domDocument = r.read(httpResponse.getEntity().getContent());
        // durchhangeln bis zur passenden Hierarchiestufe
        Element multistatus = traverseExistingElements(domDocument.getRootElement(),
            multistatusPath);
        if(null != multistatus) {
            for(@SuppressWarnings("rawtypes")
            Iterator iter = multistatus.elementIterator("response"); iter.hasNext();) {
                Element elem = (Element)iter.next();
                Element e = traverseExistingElements(elem, addressDataPath);
                String s = trimWhiteSpaces(e.getStringValue());
                if(null != s)
                    System.out.println(s);
            }
        }
    }

    /**
     * trimWhiteSpaces entfernt alle führenden 
     * und abschliessenden Leerzeichen, Tabs und Zeilenumbrüche.
     * 
     * @param stringValue
     * @return
     */
    private static String trimWhiteSpaces(String stringValue) {
        final String whiteSpaces = " \t\n\r";
        final int max = stringValue.length() - 1;
        int startPos = -1;
        for(int i = 0; i <= max; i++ ) {
            char ch = stringValue.charAt(i);
            if(0 > whiteSpaces.indexOf(ch)) {
                startPos = i;
                break;
            }
        }
        if(0 <= startPos) {
            int endPos = -1;
            for(int i = max; i >= 0; i-- ) {
                char ch = stringValue.charAt(i);
                if(0 > whiteSpaces.indexOf(ch)) {
                    endPos = i;
                    break;
                }
            }
            if(0 <= endPos)
                return stringValue.substring(startPos, endPos + 1);
        }

        return null;
    }

    private static final QName[] multistatusPath = new QName[1];
    static {
        multistatusPath[0] = new QName("multistatus");
    }

    private static final QName[] addressDataPath = new QName[3];
    static {
        addressDataPath[0] = new QName("propstat");
        addressDataPath[1] = new QName("prop");
        addressDataPath[2] = new QName("VC:address-data");
    }

    /**
     * traverseExistingElements hangelt sich entlang der gebenene Tags durch den DOM-Baum. <br>
     * Existieren die gegeben Elemente nicht, wird das Traversieren abgebrochen.
     *  
     * @param root das Haupt-/Elternelement, bei dem begonnen wird
     * @param levels die Stufen (Elemente) an denen entlang gegangen wird 
     * @return das letzte gefundene Element aus den <code>levels</code> 
     */
    private static final Element traverseExistingElements(final Element root, QName[] levels) {
        int i = 0;
        Element parent = root;
        Element e;
        while(null != parent && (i < levels.length)) {
            e = parent.element(levels[i].getName());
            if(null == e) {
                // wenn das Kind-Element nicht existiert, dann Routine beenden
                return parent;
            }
            i++ ;
            parent = e;
        }
        return parent;
    }

    /**
     * initSSL initialisiert den Keystore
     * 
     * @param keystore - Dateiname des keystores
     * @return
     */
    private final static SSLConnectionSocketFactory initSSL(String keystore)
        throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
        KeyManagementException, CertificateException, IOException {

        if(null == keystore)
            return null;

        InputStream in = new FileInputStream(keystore);
        byte[] ksData = readStream2Buffer(in);
        if(null == ksData || 0 == ksData.length)
            return null;
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new ByteArrayInputStream(ksData), "keystore".toCharArray());
        tmf.init(keyStore);
        TrustManager[] tms = tmf.getTrustManagers();
        if(null == tms)
            return null;
        SSLContext sslc = SSLContext.getInstance("TLS");
        sslc.init(null, tms, null);
        SSLContext.setDefault(sslc);
        return new SSLConnectionSocketFactory(sslc, new StrictHostnameVerifier());
    }

    private static int BUFFER_LENGTH = 4096;

    /**
    * readStream2Buffer liest einen Stream in ein Byte-Array.<br>
    * Nach dem Lesen wird der Stream geschlossen.
    * 
    * @param in der zu lesende InputStream
    * @return das erstellte Byte-Array 
    */
    private static byte[] readStream2Buffer(InputStream in) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream(1024);
        BufferedInputStream bis = new BufferedInputStream(in);

        try {
            int lastLength = 0;
            do {
                final byte[] spByte = new byte[BUFFER_LENGTH];
                lastLength = bis.read(spByte);
                if(lastLength >= 0) {
                    os.write(spByte, 0, lastLength);
                }
            } while(lastLength >= 0);
        } finally {
            in.close();
        }

        return os.toByteArray();
    }

    /**
     * ReportMethod für den Download des Adressbuchs erforderlich.
     */
    private final static class ReportMethod extends HttpEntityEnclosingRequestBase {

        public final static String METHOD_NAME = "REPORT";

        public ReportMethod(String uri){
            super();
            setURI(URI.create(uri));
        }

        @Override
        public String getMethod() {
            return METHOD_NAME;
        }

        public void setRequestBody(String send) {
            setEntity(new ByteArrayEntity(send.getBytes(), ContentType.TEXT_XML));
        }
    }
}
