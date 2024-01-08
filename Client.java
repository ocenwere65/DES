package des_app;

import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.DatatypeConverter;

public class Client {
    
    //two variables needed for socket programming
    public static final String SERVER_IP = "localhost";
    public static final int SERVER_PORT = 9001;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    private static SecretKey KEY; //secret key
        
    public static void main(String args[]) throws IOException{
        Scanner console = new Scanner(System.in); //declare Scnner variable
        Scanner readKey; //Scanner variable to read from text file
        String writeKey;
        PrintStream textFile; //to print key to text file
        
        Socket s = new Socket(SERVER_IP, SERVER_PORT); //establish socket connection with the server
        PrintWriter output = new PrintWriter(s.getOutputStream(), true);
        
        try{
            KEY = KeyGenerator.getInstance("DES").generateKey(); //call Key generator method to construct key
            writeKey = Base64.getEncoder().encodeToString(KEY.getEncoded()); //convert secret kay variable to string
            textFile = new PrintStream(new File("Key.txt")); //generate new text file
            textFile.println(writeKey); //print string to file
        }catch(Exception e){
            System.out.println();
        }
        
        try{
            //read message from server and print response
            BufferedReader input = new BufferedReader( new InputStreamReader(s.getInputStream()));
            String serverResponse = input.readLine();
            System.out.println(serverResponse + "\n");
            while(true){
                String clientResponse = console.nextLine(); //take in user input
                
                //to end while loop type 'Goodbye'
                if(clientResponse.equalsIgnoreCase("Goodbye")) break;
                
                //ecrypt user input
                try{
                    readKey = new Scanner(new File("Key.txt")); //initialize Scanner variable to read from existing key file
                    encryption(clientResponse, readKey, output); //call encyption function
                }catch(FileNotFoundException e){ //handle file not found exception
                    System.out.println("File not found.");
                }
                
                //read ciphertext from server
                BufferedReader rep = new BufferedReader( new InputStreamReader(s.getInputStream()));
                serverResponse = rep.readLine();
                System.out.println("\nReceived ciphertext is: " + serverResponse);
                
                byte[] recvText = DatatypeConverter.parseHexBinary(serverResponse);
                decryption(recvText); //call decryption method to decrypt ciphertext
            }
        }finally{
            console.close(); //close Scanner variable
            s.close(); //close socket connection
        }
                
    }
        
    //method encrypts user text and prints key, plaintext and ciphertext onscreen
    public static void encryption(String msg, Scanner str, PrintWriter p){ 
        String s = str.nextLine(); //read line from text file
        System.out.println("\nKey is: " + s);
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
    
    //method decrypts ciphertext prints to monitor
    public static void decryption(byte []enMsg){
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
}
