package des_app;

import static des_app.Client.encryption;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Server {
    
    //port number
    public static final int PORT = 9001;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    private static SecretKey KEY; //secret key
    
    public static void main(String args[]) throws IOException{
        ServerSocket listener = new ServerSocket(PORT); //set up server socket
        Scanner readKey, serverInput; //scanner variables
        String str;
        
        System.out.println("[SERVER] Waiting for client connection ...");
        Socket client = listener.accept(); //client is connected with server
        System.out.println("[SERVER] Accept new connection from 127.0.0.1");
        
        //once connection is established, print text to client
        PrintWriter output = new PrintWriter(client.getOutputStream(), true);
        output.println("Type message\n\n"); //prints message to client
        
        try{
            while(true){
                //read ciphertext
                BufferedReader input = new BufferedReader(new InputStreamReader(client.getInputStream()));
                String clientResponse = input.readLine();
                
                if(clientResponse == null) break; //if client says 'GoodBye' break out of loop
                System.out.println("\nReceived ciphertext is: " + clientResponse);
                
                //the ciphertext, in hex, must be converted to bytes
                byte[] recvText = DatatypeConverter.parseHexBinary(clientResponse);
                
                //decrypt ciphertext from client
                try{
                    readKey = new Scanner(new File("Key.txt")); //initialize Scanner variable to read from existing key file
                    str = readKey.nextLine();
                    decryption(recvText, str); //call encyption function
                    readKey.close();
                }catch(FileNotFoundException e){ //handle file not found exception
                    System.out.println("File not found.");
                }
                
                //type new message
                serverInput = new Scanner(System.in);
                String rep = serverInput.nextLine();
                
                //encrypt message
                encryption(rep, output);
            }
        }finally{
            client.close();
            listener.close();
        }
                
    }
    
    //method decrypts user text and prints message
    public static void decryption(byte []enMsg, String s2){
        byte []b = Base64.getDecoder().decode(s2); //convert string to secret key variable
        KEY = new SecretKeySpec(b, 0, b.length, "DES"); //initialize secret key variable
        try{
            decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            decrypt.init(Cipher.DECRYPT_MODE, KEY); //initialized Cipher variable to decrypt mode with secret key as parameter
            byte []deMsg = decrypt.doFinal(enMsg); //derypt text
            System.out.println("Received plaintext is: " + new String(deMsg) + "\n");
        }catch(NoSuchAlgorithmException e){ //handle multiple exceptions
            System.out.println("No such algorithm.");
        }catch(NoSuchPaddingException e){
            System.out.println("No such padding.");
        }catch(BadPaddingException e){
            System.out.println("Bad padding.");
        }catch(IllegalBlockSizeException e){
            System.out.println("Illegal block size.");
        }catch(IllegalArgumentException e){
            System.out.println("Illegal argument size.");
        }catch(InvalidKeyException e){
            System.out.println("Invalid key.");
        }catch(Exception e){
            System.out.println("Exception.");
        }
    }
    
    //method encrypts user text and prints key, plaintext and ciphertext onscreen
    public static void encryption(String msg, PrintWriter p){ 
        System.out.println("\nKey is: " + Base64.getEncoder().encodeToString(KEY.getEncoded()));
        System.out.println("Sent plaintext is: " + msg);
        try{
            encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            encrypt.init(Cipher.ENCRYPT_MODE, KEY); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []text = msg.getBytes();
            byte []enMsg = encrypt.doFinal(text); //ecrypt text
            System.out.println("Sent cyphertext is: " + DatatypeConverter.printHexBinary(enMsg));
            p.println(DatatypeConverter.printHexBinary(enMsg));
        }catch(NoSuchAlgorithmException e){ //handle multiple exceptions
            System.out.println("No such algorithm.");
        }catch(NoSuchPaddingException e){
            System.out.println("No such padding.");
        }catch(BadPaddingException e){
            System.out.println("Bad padding.");
        }catch(InvalidKeyException e){
            System.out.println("Invalid key.");
        }catch(IllegalBlockSizeException e){
            System.out.println("Illegal block size.");
        }
    }
}
