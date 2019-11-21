package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {


        Scanner sc = new Scanner(System.in);
    int len = 1024;
    String mensaje = sc.nextLine();
    byte[] mensajeByte = mensaje.getBytes();
    KeyPair keyPair = randomGenerate(len);

    byte[] datosEnc = encryptData(mensajeByte, keyPair.getPublic());
    byte[] mensajeDesByte = decryptData(datosEnc, keyPair.getPrivate());
        System.out.println(new String(mensajeDesByte));


        //  2
        String ksFile = "/home/dam2a/.keystore";
        String ksPwd = "daniel";

        KeyStore keystoredani = loadKeyStore(ksFile, ksPwd);
        Enumeration<String> enumeration = keystoredani.aliases();





        System.out.println(keystoredani.getType() + "\n");


        while (enumeration.hasMoreElements()){
            String s = enumeration.nextElement();
            System.out.println(s);
        }

        System.out.println(keystoredani.getCertificate(keystoredani.aliases().nextElement()) + "\n");
        System.out.println(keystoredani.size() + "\n");
        System.out.println(keystoredani.getKey("mykey", ksPwd.toCharArray()).getAlgorithm());


        // keystore


        SecretKey sk = keygenKeyGeneration(128);


        char[] pw = "daniel".toCharArray();
        KeyStore.SecretKeyEntry ske = new KeyStore.SecretKeyEntry(sk);
        KeyStore.ProtectionParameter kspp = new KeyStore.PasswordProtection(pw);
        keystoredani.setEntry("keyjava", ske, kspp);

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keystoredani.store(fos, pw);
            fos.flush();
        }


        // 3

        PublicKey pub = getPublicKey("/home/dam2a/keystore_andresbravo.cer");

        System.out.println(pub);


        //5

        byte[] datosbytes = "datos".getBytes();

        PrivateKey pvk = keyPair.getPrivate();

        byte[] signed = signData(datosbytes,pvk);

        System.out.println(new String(signed));


        // 6

        PublicKey pubkey = keyPair.getPublic();

        boolean a = validateSignature(datosbytes,signed,pubkey);

        System.out.println(a);


        //ultimo

        KeyPair newkeypair = randomGenerate(len);

        PublicKey pubKey = newkeypair.getPublic();
        PrivateKey privateKey = newkeypair.getPrivate();

        byte[][] claveencriptada = encryptWrappedData(datosbytes,pubKey);


        byte[]  clavedesencriptada = decryptWrappedData(claveencriptada,privateKey);

        System.out.println(new String(clavedesencriptada));













    }


    public static PublicKey getPublicKey(String archivo) throws FileNotFoundException, CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(archivo);
        Certificate cer = certificateFactory.generateCertificate(fis);
        return cer.getPublicKey();
    }





    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }





    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }




    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] data, PrivateKey pub) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, pub);
            decryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error desxifrant: " + ex);
        }
        return decryptedData;
    }


    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    public static byte[] decryptWrappedData(byte[][] data, PrivateKey pub) {
        byte[] decWrappedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, pub); // Inicia el Unwrap de la clave privada
            Key skey = cipher.unwrap(data[1],"AES",Cipher.SECRET_KEY); // Obtiene la clave privada
            cipher = Cipher.getInstance("AES"); // Define el Algoritmo de los datos
            cipher.init(Cipher.DECRYPT_MODE, skey); // Inicia el decrypt de los datos usando la private key que hemos obtenido
            decWrappedData = cipher.doFinal(data[0]); // Desencripta los datos
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }
        return decWrappedData;
    }
}
