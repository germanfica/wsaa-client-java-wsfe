package org.example;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.rpc.ParameterMode;

import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.Base64;
import org.apache.axis.encoding.XMLType;


import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


// import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;


public class ArcaWSAAClient {

    static String invoke_wsaa (byte [] LoginTicketRequest_xml_cms, String endpoint) throws Exception {

        String LoginTicketResponse = null;
        try {

            Service service = new Service();
            Call call = (Call) service.createCall();

            //
            // Prepare the call for the Web service
            //
            call.setTargetEndpointAddress( new java.net.URL(endpoint) );
            call.setOperationName("loginCms");
            call.addParameter( "request", XMLType.XSD_STRING, ParameterMode.IN );
            call.setReturnType( XMLType.XSD_STRING );

            //
            // Make the actual call and assign the answer to a String
            //
            LoginTicketResponse = (String) call.invoke(new Object [] {
                    Base64.encode (LoginTicketRequest_xml_cms) } );


        } catch (Exception e) {
            e.printStackTrace();
        }
        return (LoginTicketResponse);
    }

    //
    // Create the CMS Message
    //
    public static byte [] create_cms (String p12file, String p12pass, String signer, String dstDN, String service, Long TicketTime) {

        PrivateKey pKey = null;
        X509Certificate pCertificate = null;
        byte [] asn1_cms = null;
        CertStore cstore = null;
        String LoginTicketRequest_xml;
        String SignerDN = null;

        //
        // Manage Keys & Certificates
        //
        try {
            // Create a keystore using keys from the pkcs#12 p12file
            KeyStore ks = KeyStore.getInstance("pkcs12");
            FileInputStream p12stream = new FileInputStream ( p12file ) ;
            ks.load(p12stream, p12pass.toCharArray());
            p12stream.close();

            // Get Certificate & Private key from KeyStore
            pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
            pCertificate = (X509Certificate)ks.getCertificate(signer);
            SignerDN = pCertificate.getSubjectDN().toString();

            // Create a list of Certificates to include in the final CMS
            ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
            certList.add(pCertificate);

            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            cstore = CertStore.getInstance("Collection", new CollectionCertStoreParameters (certList), "BC");
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        //
        // Create XML Message
        //
        LoginTicketRequest_xml = create_LoginTicketRequest(SignerDN, dstDN, service, TicketTime);

        System.out.println("Generated LoginTicketRequest XML:");
        System.out.println(LoginTicketRequest_xml);

        //
        // Create CMS Message
        //
        try {
            // Create a new empty CMS Message
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            // Add a Signer to the Message
            gen.addSigner(pKey, pCertificate, CMSSignedDataGenerator.DIGEST_SHA1);

            // Add the Certificate to the Message
            gen.addCertificatesAndCRLs(cstore);

            // Add the data (XML) to the Message
            CMSProcessable data = new CMSProcessableByteArray(LoginTicketRequest_xml.getBytes());

            // Add a Sign of the Data to the Message
            CMSSignedData signed = gen.generate(data, true, "BC");

            //
            asn1_cms = signed.getEncoded();
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return (asn1_cms);
    }

    //
    // Create XML Message for AFIP wsaa
    //
    public static String create_LoginTicketRequest(String SignerDN, String dstDN, String service, Long TicketTime) {

        String LoginTicketRequest_xml;

        // Obtener la fecha actual
        Date GenTime = new Date();

        // Configurar tiempos de generación y expiración con un desfase de 10 minutos
        GregorianCalendar gentime = new GregorianCalendar();
        GregorianCalendar exptime = new GregorianCalendar();
        gentime.setTime(new Date(GenTime.getTime() - 10 * 60 * 1000)); // Resta 10 minutos
        exptime.setTime(new Date(GenTime.getTime() + 10 * 60 * 1000)); // Suma 10 minutos

        // Convertir GregorianCalendar a XMLGregorianCalendar
        DatatypeFactory datatypeFactory = null;
        try {
            datatypeFactory = DatatypeFactory.newInstance();
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }
        XMLGregorianCalendar XMLGenTime = datatypeFactory.newXMLGregorianCalendar(gentime);
        XMLGregorianCalendar XMLExpTime = datatypeFactory.newXMLGregorianCalendar(exptime);

        // Generar el UniqueId
        String UniqueId = String.valueOf(GenTime.getTime() / 1000);

        // Construir el XML del LoginTicketRequest
        LoginTicketRequest_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<loginTicketRequest version=\"1.0\">"
                + "<header>"
                + "<source>" + SignerDN + "</source>"
                + "<destination>" + dstDN + "</destination>"
                + "<uniqueId>" + UniqueId + "</uniqueId>"
                + "<generationTime>" + XMLGenTime.toXMLFormat().split("\\.")[0] + "</generationTime>"
                + "<expirationTime>" + XMLExpTime.toXMLFormat().split("\\.")[0] + "</expirationTime>"
                + "</header>"
                + "<service>" + service + "</service>"
                + "</loginTicketRequest>";

        return LoginTicketRequest_xml;
    }
}
