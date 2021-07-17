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
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
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
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KDC {
	
	private static final int PORT = 3000;

	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, ClassNotFoundException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		String osName=System.getProperty("os.name","generic").toLowerCase();
		if(osName.indexOf("win") >= 0) {
			osName="windows";
		}
		else if(osName.indexOf("nix") >= 0 || osName.indexOf("nux") >= 0 || osName.indexOf("aix") > 0 ) {
			osName="unix";
		}
		if(osName.equals("windows")) {
			ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", "mkdir cert & mkdir keys & mkdir logs");
			builder.redirectErrorStream(true);
			Process process = builder.start();
			while(process.isAlive()) continue;
		}
		else if(osName.equals("unix")) {
			ProcessBuilder builder = new ProcessBuilder("bash", "-c", "mkdir cert && mkdir keys && mkdir logs");
			builder.redirectErrorStream(true);
			Process process = builder.start();
			while(process.isAlive()) continue;
		}
		
		System.out.print("Creating keys and certificates.");
		
		createKeyPair("kdc",osName);
		createKeyPair("alice",osName);
		createKeyPair("web",osName);
		createKeyPair("mail",osName);
		createKeyPair("database",osName);
		
		System.out.print(".");
		
		getPrivateKey("kdc","selfsigned","passwd");
		getPrivateKey("alice","alice","passwd");
		getPrivateKey("web","web","passwd");
		getPrivateKey("mail","mail","passwd");
		getPrivateKey("database","database","passwd");
		
		System.out.println(".");
		
		createSignedCertificate("kdc",osName);
		createSignedCertificate("alice",osName);
		createSignedCertificate("web",osName);
		createSignedCertificate("mail",osName);
		createSignedCertificate("database",osName);
		
		deleteUnnecessaryFile("cert/kdc.srl");
		deleteUnnecessaryFile("keys/kdc.jks");
		deleteUnnecessaryFile("keys/kdcrkey.pem");
		deleteUnnecessaryFile("keys/kdc.p12");
		deleteUnnecessaryFile("cert/alice.csr");
		deleteUnnecessaryFile("keys/alice.jks");
		deleteUnnecessaryFile("cert/web.csr");
		deleteUnnecessaryFile("keys/web.jks");
		deleteUnnecessaryFile("cert/mail.csr");
		deleteUnnecessaryFile("keys/mail.jks");
		deleteUnnecessaryFile("cert/database.csr");
		deleteUnnecessaryFile("keys/database.jks");
		
		System.out.println("Keys and certificates are created!");
		
		File file = new File("logs/KDC_Log.txt");
        if (!file.exists()) {
            file.createNewFile();
        }
        FileWriter fileWriter = new FileWriter(file, true);
        BufferedWriter bWriter = new BufferedWriter(fileWriter);
        
        String password=createPasswd();
        
        File file2 = new File("logs/passwd");
        if (!file2.exists()) {
            file2.createNewFile();
        }
        FileWriter fileWriter2 = new FileWriter(file2, false);
        BufferedWriter bWriter2 = new BufferedWriter(fileWriter2);
        bWriter2.write(getSHA1(password));
        bWriter2.close();
        
        bWriter.append(getDate()+" "+password+"\n");
        bWriter.flush();
        
        ServerSocket KDCServer = new ServerSocket(PORT);
        System.out.println("Waiting for Alice...");
        Socket client = KDCServer.accept();
        System.out.println("Connected to Alice...");
		OutputStream output = client.getOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(output);
        InputStream input = client.getInputStream();
		ObjectInputStream objectInputStream = new ObjectInputStream(input);
		String message, decrypted, sessionKey, time, forAlice, ticket;
		String[] split1, split2;
        while (true) {
        	try {
        		if(client.isClosed()) {
        			System.out.println("Waiting for Alice...");
            		client = KDCServer.accept();
            		System.out.println("Connected to Alice!");
        			output = client.getOutputStream();
        	        objectOutputStream = new ObjectOutputStream(output);
        	        input = client.getInputStream();
        			objectInputStream = new ObjectInputStream(input);
        		}
    			while(true) {
    				message = (String) objectInputStream.readObject();
    				bWriter.append(getDate()+" Alice->KDC : "+message+"\n");
    				bWriter.flush();
    				split1 = message.split(",");
    				decrypted=decryptRSA(split1[1],readOwnPrivateKeyFile("keys/kdc.txt"));
    				split2 = decrypted.split(",");
    				bWriter.append(getDate()+" Message Decrypted : "+split2[0]+","+split2[1]+","+split2[2]+","+split2[3]+"\n");
    				bWriter.flush();
    				if(readOwnPrivateKeyFile("logs/passwd").equals(getSHA1(split2[1])) &&
    						(split2[2].equals("Mail") || split2[2].equals("Web") || split2[2].equals("Database"))) {
    					bWriter.append(getDate()+" KDC->Alice : Password Verified\n");
    					bWriter.flush();
    					break;
    				}
    				else {
    					if(readOwnPrivateKeyFile("logs/passwd").equals(getSHA1(split2[1]))) {
    						objectOutputStream.writeObject("wrong_servername");
    						bWriter.append(getDate()+" KDC->Alice : Server Name Not Identified\n");
    						bWriter.flush();
    					}
    					else {
    						objectOutputStream.writeObject("wrong_password");
    						bWriter.append(getDate()+" KDC->Alice : Password Denied\n");
    						bWriter.flush();
    					}
    				}
    			}
    			sessionKey=generateSessionKey();
    			time=getDate();
    			forAlice=encryptRSA(sessionKey+","+split2[2]+","+time,"cert/alice.cert");
    			ticket=encryptRSA("Alice,"+split2[2]+","+time+","+sessionKey,"cert/"+split2[2].toLowerCase()+".cert");
    			bWriter.append(getDate()+" KDC->Alice : "+sessionKey+","+split2[2]+","+time+"\n");
    			bWriter.append(getDate()+" KDC->Alice : "+forAlice+","+ticket+"\n");
    			bWriter.flush();
    			objectOutputStream.writeObject(forAlice+","+ticket);
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
	
	public static String createPasswd(){
		final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		SecureRandom random = new SecureRandom();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 8; i++) {
			int random2 = random.nextInt(chars.length());
			sb.append(chars.charAt(random2));
		}
		return sb.toString();
	}
	
	public static String getSHA1(String input) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] messageDigest = md.digest(input.getBytes());
		BigInteger no = new BigInteger(1, messageDigest);
		String hashtext = no.toString(16);
		while (hashtext.length() < 32) {
			hashtext = "0" + hashtext;
		}
		return hashtext;
	}
	
	public static void createKeyPair(String name, String osName) throws IOException {
		String genKeyPair;
		if(name.equals("kdc")) {
			genKeyPair="keytool -genkeypair -noprompt -trustcacerts -keysize 2048 -keyalg RSA -alias selfsigned"
					+" -dname  CN=java -storetype PKCS12 -keystore keys/"+name+".jks -keypass passwd -storepass passwd";
		}
		else {
			genKeyPair="keytool -genkeypair -noprompt -keysize 2048 -keyalg RSA -alias "+name
					+" -dname  CN=java -storetype PKCS12 -keystore keys/"+name+".jks -keypass passwd -storepass passwd";
		}
		if(osName.equals("windows")) {
			ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", genKeyPair);
			builder.redirectErrorStream(true);
			Process process = builder.start();
			while(process.isAlive()) continue;
		}
		else if(osName.equals("unix")) {
			ProcessBuilder builder = new ProcessBuilder("bash", "-c", genKeyPair);
			builder.redirectErrorStream(true);
			Process process = builder.start();
			while(process.isAlive()) continue;
		}
	}
	
	public static void createSignedCertificate(String name, String osName) throws IOException {
		if(name.equals("kdc")) {
			String command1="keytool -export -alias selfsigned -keystore keys/kdc.jks -rfc -file cert/kdc.cert"
		+" -keypass passwd -storepass passwd";
			String command2="keytool -importkeystore -srckeystore keys/kdc.jks -destkeystore keys/kdc.p12"
		+" -deststoretype PKCS12 -deststorepass passwd -srcstorepass passwd";
			String command3="openssl pkcs12 -in keys/kdc.p12 -nodes -nocerts -out keys/kdcrkey.pem -passin pass:passwd";
			if(osName.equals("windows")) {
				ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", command1+" & "+command2+" & "+command3);
				builder.redirectErrorStream(true);
				Process process = builder.start();
				while(process.isAlive()) continue;
			}
			else if(osName.equals("unix")) {
				ProcessBuilder builder = new ProcessBuilder("bash", "-c", command1+" && "+command2+" && "+command3);
				builder.redirectErrorStream(true);
				Process process = builder.start();
				while(process.isAlive()) continue;
			}
		}
		else {
			String command1="keytool -keystore keys/"+name+".jks -certreq -alias "+name+" -keyalg rsa -file cert/"+name+".csr -storepass passwd";
			String command2="openssl x509 -req -CA cert/kdc.cert -CAkey keys/kdcrkey.pem -in cert/"+name+".csr -out cert/"+name+".cert -days 365 -CAcreateserial";
			if(osName.equals("windows")) {
				ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", command1+" & "+command2);
				builder.redirectErrorStream(true);
				Process process = builder.start();
				while(process.isAlive()) continue;
			}
			else if(osName.equals("unix")) {
				ProcessBuilder builder = new ProcessBuilder("bash", "-c", command1+" && "+command2);
				builder.redirectErrorStream(true);
				Process process = builder.start();
				while(process.isAlive()) continue;
			}
		}
	}
	
	public static String getPublicKey(String certPath) throws FileNotFoundException, CertificateException {
		FileInputStream fin = new FileInputStream(certPath);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
		PublicKey pk = certificate.getPublicKey();
		return Base64.getEncoder().encodeToString(pk.getEncoded());
	}
	
	public static void getPrivateKey(String keyFileName, String alias, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        String  keystoreFile ="keys/"+keyFileName+".jks";
        String  exportedFile ="keys/"+keyFileName+".txt";

        char[] keyPassword = new char[password.length()];
        for(int count=0;count<keyPassword.length;count++) {
           keyPassword[count] = password.charAt(count);
        }
        
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream FISforDEL=new FileInputStream(keystoreFile);
        keystore.load(FISforDEL, keyPassword);
        Key key = keystore.getKey(alias, keyPassword);
        byte[] encoded = Base64.getEncoder().encode(key.getEncoded());
        String encodedString = new String(encoded);
        FileWriter fw = new FileWriter(exportedFile);
        fw.write(encodedString);
        fw.close();
        FISforDEL.close();
    }
	
	public static void deleteUnnecessaryFile(String path) {
		try  {         
			File jksFile= new File(path);
			if(!jksFile.delete()) System.out.println("WARNING: "+path+" CANNOT BE DELETED!");
		}  
		catch(Exception e) {  
			e.printStackTrace();  
		}  
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
    
    public static String generateSessionKey() throws NoSuchAlgorithmException {
    	KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		return encodedKey;
    }

}
