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
import java.net.Socket;
import java.net.UnknownHostException;
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
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Alice {
	
	private static final String IP = "127.0.0.1";
	private static final int KDC_PORT = 3000;
	private static final int MAIL_PORT = 3001;
	private static final int WEB_PORT = 3002;
	private static final int DB_PORT = 3003;
	
    public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
    	
    	boolean KDCConnect=false, MailConnect=false, WebConnect=false, DatabaseConnect=false;
    	Socket KDCSocket=null, MailSocket=null, WebSocket=null, DBSocket=null;
    	OutputStream KDCOutput=null, MailOutput=null, WebOutput=null, DBOutput=null;
    	ObjectOutputStream KDCOS=null, MailOS=null, WebOS=null, DBOS=null;
    	InputStream KDCInput=null, MailInput=null, WebInput=null, DBInput=null;
    	ObjectInputStream KDCIS=null, MailIS=null, WebIS=null, DBIS=null;
    	
    	try {
    		KDCSocket = new Socket(IP, KDC_PORT);
        	KDCOutput = KDCSocket.getOutputStream();
        	KDCOS = new ObjectOutputStream(KDCOutput);
        	KDCInput = KDCSocket.getInputStream();
        	KDCIS = new ObjectInputStream(KDCInput);
        	KDCConnect=true;
    	}catch(Exception e) {
    		System.out.println("Cannot connect to KDC Server!\nSystem shut down!");
    		return;
    	}
    	
    	try {
    		MailSocket = new Socket(IP, MAIL_PORT);
        	MailOutput = MailSocket.getOutputStream();
        	MailOS = new ObjectOutputStream(MailOutput);
        	MailInput = MailSocket.getInputStream();
        	MailIS = new ObjectInputStream(MailInput);
        	MailConnect=true;
    	}catch(Exception e) {
    		System.out.println("Cannot connect to Mail Server!");
    	}
    	
    	try {
    		WebSocket = new Socket(IP, WEB_PORT);
        	WebOutput = WebSocket.getOutputStream();
        	WebOS = new ObjectOutputStream(WebOutput);
        	WebInput = WebSocket.getInputStream();
        	WebIS = new ObjectInputStream(WebInput);
        	WebConnect=true;
    	}catch(Exception e) {
    		System.out.println("Cannot connect to Web Server!");
    	}
    	
    	try {
    		DBSocket = new Socket(IP, DB_PORT);
        	DBOutput = DBSocket.getOutputStream();
        	DBOS = new ObjectOutputStream(DBOutput);
        	DBInput = DBSocket.getInputStream();
        	DBIS = new ObjectInputStream(DBInput);
        	DatabaseConnect=true;
    	}catch(Exception e) {
    		System.out.println("Cannot connect to Database Server!");
    	}
    	
    	File file = new File("logs/Alice_Log.txt");
        if (!file.exists()) {
            file.createNewFile();
        }
        FileWriter fileWriter = new FileWriter(file, true);
        BufferedWriter bWriter = new BufferedWriter(fileWriter);
    	
    	Scanner scan = new Scanner(System.in);
    	String passwd, serverName, message, nonceEnc, nonceDec,plainVal,encVal;
    	String[] split1,split2,split3;
    	int nonceInt;
    	while(true) {
    		try{
    			while(true) {
                	System.out.print("Enter password: ");
                    passwd = scan.nextLine();
                    System.out.print("Enter a server name: ");
                    serverName = scan.nextLine();
                    plainVal="Alice,"+passwd+","+serverName+","+getDate();
                    bWriter.append(getDate()+" Alice->KDC : "+plainVal+"\n");
                    bWriter.flush();
                    encVal=encryptRSA(plainVal,"cert/kdc.cert");
                    bWriter.append(getDate()+" Alice->KDC : Alice,"+encVal+"\n");
                    bWriter.flush();
                    KDCOS.writeObject("Alice,"+encVal);
                    message = (String) KDCIS.readObject();
                    if(message.equals("wrong_password")) {
                    	bWriter.append(getDate()+" KDC->Alice : Password Denied\n");
                    	bWriter.flush();
                    	System.out.println("Wrong password attempt!");
                    }
                    else if(message.equals("wrong_servername")) {
                    	bWriter.append(getDate()+" KDC->Alice : Server Name Not Identified\n");
                    	bWriter.flush();
                    	System.out.println("Please type Mail, Web or Database for server name!");
                    }
                    else {
                    	bWriter.append(getDate()+" KDC->Alice : Password Verified\n");
                    	bWriter.flush();
                    	break;
                    }
                }
    			bWriter.append(getDate()+" KDC->Alice : "+message+"\n");
    			bWriter.flush();
                split1=message.split(","); //split1[1] ===> Ticket
                message=decryptRSA(split1[0],readOwnPrivateKeyFile("keys/alice.txt"));
                bWriter.append(getDate()+" Message Decrypted : "+message+"\n");
                bWriter.flush();
                split2=message.split(","); //split2[0] ===> Session Key
                if(split2[1].equals("Mail")) {
                	try {
                		if(!MailConnect) {
                        	MailSocket = new Socket(IP, MAIL_PORT);
                            MailOutput = MailSocket.getOutputStream();
                            MailOS = new ObjectOutputStream(MailOutput);
                            MailInput = MailSocket.getInputStream();
                            MailIS = new ObjectInputStream(MailInput);
                            MailConnect=true;
                    	}
                		nonceInt=createNonce();
                		bWriter.append(getDate()+" Alice->Mail : Alice,"+Integer.toString(nonceInt)+"\n");
                		bWriter.flush();
                		nonceEnc=encryptAES(Integer.toString(nonceInt),split2[0]);
                		bWriter.append(getDate()+" Alice->Mail : Alice,"+split1[1]+","+nonceEnc+"\n");
                		bWriter.flush();
                    	MailOS.writeObject("Alice,"+split1[1]+","+nonceEnc);
                    	message = (String) MailIS.readObject();
                    	bWriter.append(getDate()+" Mail->Alice : "+message+"\n");
                    	bWriter.flush();
                    	message=decryptAES(message,split2[0]);
                    	split3=message.split(",");
                    	if(nonceInt+1==Integer.parseInt(split3[0])) {
                    		nonceDec=split3[1];
                    		bWriter.append(getDate()+" Message Decrypted : N1 is OK, N2="+nonceDec+"\n");
                    		nonceDec=Integer.toString(Integer.parseInt(nonceDec)+1);
                    		bWriter.append(getDate()+" Alice->Mail : "+nonceDec+"\n");
                    		bWriter.flush();
                    		message=encryptAES(nonceDec,split2[0]);
                    		bWriter.append(getDate()+" Alice->Mail : "+message+"\n");
                    		bWriter.flush();
                    		MailOS.writeObject(message);
                    		message = (String) MailIS.readObject();
                    		if(message.equals("success")) {
                    			bWriter.append(getDate()+" Mail->Alice : Authentication is completed!\n");
                    			System.out.println("Authentication is completed!");
                    		}
                    		else {
                    			bWriter.append(getDate()+" Mail->Alice : Authentication is failed!\n");
                    			System.out.println("Authentication is failed!");
                    		}
                    		bWriter.flush();
                    	}
                    	else {
                    		bWriter.append(getDate()+" Alice->Mail : Authentication is failed!\n");
                    		bWriter.flush();
                    		System.out.println("Authentication is failed!");
                    		MailOS.writeObject("fail");
                    	}
                	}catch(Exception e) {
                		System.out.println("Cannot connect to Mail Server!");
                		MailConnect=false;
                		continue;
                	}
                }
                else if(split2[1].equals("Web")) {
                	try {
                		if(!WebConnect) {
                        	WebSocket = new Socket(IP, WEB_PORT);
                            WebOutput = WebSocket.getOutputStream();
                            WebOS = new ObjectOutputStream(WebOutput);
                            WebInput = WebSocket.getInputStream();
                            WebIS = new ObjectInputStream(WebInput);
                            WebConnect=true;
                    	}
                		nonceInt=createNonce();
                		bWriter.append(getDate()+" Alice->Web : Alice,"+Integer.toString(nonceInt)+"\n");
                		bWriter.flush();
                		nonceEnc=encryptAES(Integer.toString(nonceInt),split2[0]);
                		bWriter.append(getDate()+" Alice->Web : Alice,"+split1[1]+","+nonceEnc+"\n");
                		bWriter.flush();
                    	WebOS.writeObject("Alice,"+split1[1]+","+nonceEnc);
                    	message = (String) WebIS.readObject();
                    	bWriter.append(getDate()+" Web->Alice : "+message+"\n");
                    	bWriter.flush();
                    	message=decryptAES(message,split2[0]);
                    	split3=message.split(",");
                    	if(nonceInt+1==Integer.parseInt(split3[0])) {
                    		nonceDec=split3[1];
                    		bWriter.append(getDate()+" Message Decrypted : N1 is OK, N2="+nonceDec+"\n");
                    		nonceDec=Integer.toString(Integer.parseInt(nonceDec)+1);
                    		bWriter.append(getDate()+" Alice->Web : "+nonceDec+"\n");
                    		bWriter.flush();
                    		message=encryptAES(nonceDec,split2[0]);
                    		bWriter.append(getDate()+" Alice->Web : "+message+"\n");
                    		bWriter.flush();
                    		WebOS.writeObject(message);
                    		message = (String) WebIS.readObject();
                    		if(message.equals("success")) {
                    			bWriter.append(getDate()+" Web->Alice : Authentication is completed!\n");
                    			System.out.println("Authentication is completed!");
                    		}
                    		else {
                    			bWriter.append(getDate()+" Web->Alice : Authentication is failed!\n");
                    			System.out.println("Authentication is failed!");
                    		}
                    		bWriter.flush();
                    	}
                    	else {
                    		bWriter.append(getDate()+" Alice->Web : Authentication is failed!\n");
                    		bWriter.flush();
                    		System.out.println("Authentication is failed!");
                    		WebOS.writeObject("fail");
                    	}
                	}catch(Exception e) {
                		System.out.println("Cannot connect to Web Server!");
                		WebConnect=false;
                		continue;
                	}
                }
                else if(split2[1].equals("Database")) {
                	try {
                		if(!DatabaseConnect) {
                        	DBSocket = new Socket(IP, DB_PORT);
                            DBOutput = DBSocket.getOutputStream();
                            DBOS = new ObjectOutputStream(DBOutput);
                            DBInput = DBSocket.getInputStream();
                            DBIS = new ObjectInputStream(DBInput);
                            DatabaseConnect=true;
                    	}
                		nonceInt=createNonce();
                		bWriter.append(getDate()+" Alice->Database : Alice,"+Integer.toString(nonceInt)+"\n");
                		bWriter.flush();
                		nonceEnc=encryptAES(Integer.toString(nonceInt),split2[0]);
                		bWriter.append(getDate()+" Alice->Database : Alice,"+split1[1]+","+nonceEnc+"\n");
                		bWriter.flush();
                    	DBOS.writeObject("Alice,"+split1[1]+","+nonceEnc);
                    	message = (String) DBIS.readObject();
                    	bWriter.append(getDate()+" Database->Alice : "+message+"\n");
                    	bWriter.flush();
                    	message=decryptAES(message,split2[0]);
                    	split3=message.split(",");
                    	if(nonceInt+1==Integer.parseInt(split3[0])) {
                    		nonceDec=split3[1];
                    		bWriter.append(getDate()+" Message Decrypted : N1 is OK, N2="+nonceDec+"\n");
                    		nonceDec=Integer.toString(Integer.parseInt(nonceDec)+1);
                    		bWriter.append(getDate()+" Alice->Database : "+nonceDec+"\n");
                    		bWriter.flush();
                    		message=encryptAES(nonceDec,split2[0]);
                    		bWriter.append(getDate()+" Alice->Database : "+message+"\n");
                    		bWriter.flush();
                    		DBOS.writeObject(message);
                    		message = (String) DBIS.readObject();
                    		if(message.equals("success")) {
                    			bWriter.append(getDate()+" Database->Alice : Authentication is completed!\n");
                    			System.out.println("Authentication is completed!");
                    		}
                    		else {
                    			bWriter.append(getDate()+" Database->Alice : Authentication is failed!\n");
                    			System.out.println("Authentication is failed!");
                    		}
                    		bWriter.flush();
                    	}
                    	else {
                    		bWriter.append(getDate()+" Alice->Database : Authentication is failed!\n");
                    		bWriter.flush();
                    		System.out.println("Authentication is failed!");
                    		DBOS.writeObject("fail");
                    	}
                	}catch(Exception e) {
                		System.out.println("Cannot connect to Database Server!");
                		DatabaseConnect=false;
                		continue;
                	}
                }
        		
    		}
    		catch(Exception e) {
    			System.out.println("Oops!");
    			break;
    		}
    	}
		KDCSocket.close();
		scan.close();
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
