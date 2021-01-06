/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsatest3;

/**
 *
 * @author tonis
 */

import java.security.*;
import sun.misc.BASE64Encoder;
import java.io.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSATest3 {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        // TODO code application logic here
        //recordemos que security no tiene soporte con BC
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        //primero hay que hacer la instancia con un nuevo proveedor
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA", "BC");
        
        //inicializamos la llave
        generador.initialize(2048, new SecureRandom());
        
        //laves
        KeyPair llaves = generador.genKeyPair();
        //ahora necesitamos la llave publica y la privada
        PublicKey llavepublica = llaves.getPublic();
        PrivateKey llaveprivada = llaves.getPrivate();
        
        //vamos a guardar y cargar un archivo con el contenido de la llave publica
        guardarKey(llavepublica, "publickey.key");
        llavepublica = cargarPublicaKey("publickey.key");
        
        //vamos a guardar y cargar un archivo con el contenido de la llave privada
        guardarKey(llaveprivada, "privatekey.key");
        llaveprivada = cargarPrivadaKey("privatekey.key");
        
        //preparar la firma
        Signature firma = Signature.getInstance("SHA1WithRSA", "BC");
        
        //inicializamos la firma
        firma.initSign(llaveprivada, new SecureRandom());
        
        byte[] dato = "no se que poner".getBytes();
        byte[] dato1 = "no se que poners".getBytes();
        
        firma.update(dato);
        
        //firmamos
        byte[] firmabytes = firma.sign();
        
        //imprimimos
        System.out.println("Firma:" + new BASE64Encoder().encode(firmabytes));
        
        //verificamos
        firma.initVerify(llavepublica);
        
        firma.update(dato);
        
        System.out.println(firma.verify(firmabytes));
    }
    
    private static void guardarKey(Key llave, String archivo) throws FileNotFoundException, IOException {
        //generarme un archivo .dat
        byte[] llavepublic = llave.getEncoded();
        FileOutputStream fos = new FileOutputStream(archivo);
        fos.write(llavepublic);
        fos.close();
        
    }

    private static PublicKey cargarPublicaKey(String archivo) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        /*
        para poder exportar la llave publica es necesario codificarla mediante una codificacion
        certificada por X509 es para la certificacion de la llave
        */
        
        FileInputStream fis = new FileInputStream(archivo);
        //comprobacion si es valida 
        int numBytes = fis.available();
        byte[] bytes = new byte[numBytes];
        fis.read(bytes);
        fis.close();
        
        //para comprobar la llave
        KeyFactory keyfactory = KeyFactory.getInstance("RSA");
        //generar la subllaves
        KeySpec spec = new X509EncodedKeySpec(bytes);
        
        PublicKey llavePublic = keyfactory.generatePublic(spec);
        
        return llavePublic;
        
    }

    private static PrivateKey cargarPrivadaKey(String archivo) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        
        FileInputStream fis = new FileInputStream(archivo);
        //comprobacion si es valida 
        int numBytes = fis.available();
        byte[] bytes = new byte[numBytes];
        fis.read(bytes);
        fis.close();
        
        /*porque para la comprobacion de la llave privada, es necesario el 
        certificado por parte del estandar PKCS8 el cual nos dice el tipo 
        de codificacion que acepta una llave privada en RSA
        */
         //para comprobar la llave
        KeyFactory keyfactory = KeyFactory.getInstance("RSA");
        KeySpec spec = new PKCS8EncodedKeySpec(bytes);
        PrivateKey llavePrivate = keyfactory.generatePrivate(spec);
        return llavePrivate;
        
    }
    
}
