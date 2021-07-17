import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Web {
	
	private static final int PORT = 3002;
	
	public static void main(String[] args) throws IOException {
		ServerSocket WebServer = new ServerSocket(PORT);
        System.out.println("Waiting for Alice...");
        Socket client = WebServer.accept();
        System.out.println("Connected to Alice...");
		OutputStream output = client.getOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(output);
        InputStream input = client.getInputStream();
		ObjectInputStream objectInputStream = new ObjectInputStream(input);
		String message, nonceDec;
		String[] split1, split2;
		int nonceInt;
		
		File file = new File("logs/Web_Log.txt");
        if (!file.exists()) {
            file.createNewFile();
        }
        FileWriter fileWriter = new FileWriter(file, true);
        BufferedWriter bWriter = new BufferedWriter(fileWriter);
        
        while (true) {
        	try {
        		if(client.isClosed()) {
        			System.out.println("Waiting for Alice...");
            		client = WebServer.accept();
            		System.out.println("Connected to Alice!");
        			output = client.getOutputStream();
        	        objectOutputStream = new ObjectOutputStream(output);
        	        input = client.getInputStream();
        			objectInputStream = new ObjectInputStream(input);
        		}
        		message = (String) objectInputStream.readObject();
        		bWriter.append(getDate()+" Alice->Web : "+message+"\n");
        		bWriter.flush();
        		split1=message.split(",");
        		split2=decryptRSA(split1[1],readOwnPrivateKeyFile("keys/web.txt")).split(",");
        		bWriter.append(getDate()+" Ticket Decrypted : "+split2[0]+","+split2[1]+","+split2[2]+","+split2[3]+"\n");
        		bWriter.flush();
        		nonceDec=decryptAES(split1[2],split2[3]);
        		bWriter.append(getDate()+" Message Decrypted : N1="+nonceDec+"\n");
        		nonceDec=Integer.toString(Integer.parseInt(nonceDec)+1);
        		nonceInt=createNonce();
        		bWriter.append(getDate()+" Web->Alice : "+nonceDec+","+Integer.toString(nonceInt)+"\n");
        		bWriter.flush();
        		message=encryptAES(nonceDec+","+Integer.toString(nonceInt),split2[3]);
        		bWriter.append(getDate()+" Web->Alice : "+message+"\n");
        		bWriter.flush();
        		objectOutputStream.writeObject(message);
        		message = (String) objectInputStream.readObject();
        		if(message.equals("fail")) {
        			bWriter.append(getDate()+" Alice->Web : Authentication is failed!\n");
            		bWriter.flush();
        			System.out.println("Authentication is failed!");
        			continue;
        		}
        		else {
        			bWriter.append(getDate()+" Alice->Web : "+message+"\n");
        			bWriter.flush();
        			message=decryptAES(message,split2[3]);
        			bWriter.append(getDate()+" Message Decrypted : "+message+"\n");
        			if(nonceInt+1==Integer.parseInt(message)) {
        				bWriter.append(getDate()+" Web->Alice : Authentication is completed!\n");
        				bWriter.flush();
        				System.out.println("Authentication is completed!");
        				objectOutputStream.writeObject("success");
        			}
        			else {
        				bWriter.append(getDate()+" Web->Alice : Authentication is failed!\n");
        				bWriter.flush();
        				System.out.println("Authentication is failed!");
        				objectOutputStream.writeObject("fail");
        			}
        		}
        	}
        	catch(Exception e) {
        		System.out.println("Alice is disconnected!");
        		client.close();
        	}
		}
	}
	
	public static String getDate() {
		 Date dNow = new Date( );
	     SimpleDateFormat ft = new SimpleDateFormat ("dd.MM.yyyy HH:mm:ss");
	     return ft.format(dNow);
	}
	
	public static String getPublicKey(String certPath) throws FileNotFoundException, CertificateException {
		FileInputStream fin = new FileInputStream(certPath);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
		PublicKey pk = certificate.getPublicKey();
		return Base64.getEncoder().encodeToString(pk.getEncoded());
	}
	
	public static String readOwnPrivateKeyFile(String keyPath) throws IOException {
    	File file = new File(keyPath);
        if (!file.exists()) {
            file.createNewFile();
        }
        FileReader fr = new FileReader(file);
		BufferedReader br = new BufferedReader(fr);
		String key = br.readLine();
		br.close();
    	return key;
    }
	
	public static String encryptRSA(String data, String certPath) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, CertificateException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode((getPublicKey(certPath)).getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encVal=cipher.doFinal(data.getBytes());
		String ciphertext= Base64.getEncoder().encodeToString(encVal);
		return ciphertext;
	}
    
    public static String decryptRSA(String data, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getBytes()));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
        PrivateKey prvKey = keyFactory.generatePrivate(keySpec);
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, prvKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes())));
	}
    
    public static String encryptAES(String plaintext, String key) {
    	try {
    		Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
    		
    		String initVector="1010101010101010";
    		IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
    		SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
    		
    		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
    		byte[] encVal=cipher.doFinal(plaintext.getBytes());
    		String ciphertext= Base64.getEncoder().encodeToString(encVal);
    		return ciphertext;
    	}catch(Exception e) {
    		e.printStackTrace();
			return null;
		}
	}
	
	public static String decryptAES(String ciphertext, String key){
		try {
			Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			String initVector="1010101010101010";
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			
			cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
			byte[] decodedValue=Base64.getDecoder().decode(ciphertext);
			byte[] decValue=cipher.doFinal(decodedValue);
			String decryptedMessage=new String(decValue);
			return decryptedMessage;
		}catch(Exception e) {
			return null;
		}	
	}
	
	public static int createNonce() {
		int nonce = (int)(Math.random() * (2000000000 - 1000000000 + 1) + 1000000000);
		return nonce;
	}
	
}
