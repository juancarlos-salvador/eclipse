package cryptoAct1;

import java.lang.reflect.GenericArrayType;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class principal {
	
	// metodo para generar password
	
	public static SecretKey generarPassword(int clave, int keySize) {    
	    String text = String.valueOf(clave);
		SecretKey sKey = null;  
	    if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {    	
	      try {
	        byte[] data = text.getBytes("UTF-8");
	        MessageDigest md = MessageDigest.getInstance("SHA-256");
	        byte[] hash = md.digest(data);
	        
	        //convertimos a string de 2 caracteres
	        byte[] key = Arrays.copyOf(hash, keySize/8);
	        
	        // generamos el password
	        sKey = new SecretKeySpec(key, "AES");      
	      } catch (Exception ex) {
	        System.err.println("Error al generar el password:" + ex);  
	      }
		}
	    return sKey;   
	}
	public static void conseguirPassword(byte [] encriptado) {
		
	    
	    System.out.println("Probando claves...");
	    
	    //Se generan todas las contraseñas de dos digitos posibles y se prueban
	    
	    for (int num = 0; num < 99; num++) {
	      String pass = Integer.toString(num);
	      while (pass.length() < 2) {
	        pass = "0" + pass;  
	      }
	      
	      //Generación de la clave a partir de cada clave posible generada
	      
	      SecretKey sKey = null;
	      try {
	        byte[] data = pass.getBytes("UTF-8");
	        MessageDigest md = MessageDigest.getInstance("SHA-256");
	        byte[] hash = md.digest(data);
	        byte[] key = Arrays.copyOf(hash, 128/8);      
	        sKey = new SecretKeySpec(key, "AES");      
	      } catch (Exception ex) {
	        System.err.println("No se ha posido generar la clave:" + ex);
	      }
	      
	      //Descifrado AES
	      
	      if (sKey != null) {
	        try {  
	          Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	          cipher.init(Cipher.DECRYPT_MODE, sKey);            
	          byte[] data =  cipher.doFinal(encriptado);
	          
	          //Imprimimos el mensaje desencriptado
	          
	          System.out.print("Clave encontrada: " + pass + "\n");
	          System.out.println("Texto desencriptado por fuerza bruta: " + new String(data));
	        } catch (Exception ex) {        
	           
	        }      
	      }      
	    }    
	  }

	public static void main(String[] args) {
	
		// Declaramos variables
		
		int clave = 0;
		String mensaje;
		int espacio = 0;    //variable usada para capturar el error de salto automatico en el scan
		
		// Inicializamos el scanner
		
		Scanner scanner = new Scanner(System.in);
		
		//Pedimos que introduzca la clave de dos dígitos, sólo válidos desde el 00 al 99
		
		
		System.out.println("Introduzca una clave de dos dígitos: ");
		do {
		clave = scanner.nextInt();
		if (clave<0 || clave>99) {
			System.out.println("La clave debe estar comprendida entre 00 y 99");
			System.out.println("Intentelo de nuevo...: ");
		}
		}while (clave<0 || clave>99);
		
		System.out.println("La clave " + clave +" se intodujo con éxito");
		
		// Llamamos al generador de passwords para que nos cree uno con la clave introducida
		
		SecretKey password = generarPassword(clave,128);
		
		System.out.println("El password generado es: " + password + "\n\n");
		
		//Pedimos el texto a encriptar
		
		System.out.println("Introduzca un texto para encriptar: \n\n");
		
		mensaje = scanner.nextLine();
		mensaje = scanner.nextLine();

		// Se obtiene un cifrador AES
	      Cipher aes;
		try {
			aes = Cipher.getInstance("AES");
		

	      // Se inicializa para encriptacion y se encripta el texto,
	      // que debemos pasar como bytes.
	      
			aes.init(Cipher.ENCRYPT_MODE, password);
		
	      byte[] encriptado = aes.doFinal(mensaje.getBytes());
	     
	      
	      // Se escribe byte a byte en hexadecimal el texto
	      // encriptado para ver su pinta.
	      System.out.print("Texto encriptado: \n");
	      for (byte b : encriptado) { 
	         System.out.print(Integer.toHexString(0xFF & b));
	      }
	      System.out.println("\n");

	      // Se iniciliza el cifrador para desencriptar, con la
	      // misma clave y se desencripta
	      aes.init(Cipher.DECRYPT_MODE, password);
	      byte[] desencriptado = aes.doFinal(encriptado);

	      // Texto obtenido, igual al original.
	      System.out.print("Texto desencriptado: \n");
	      System.out.println(new String(desencriptado)+"\n");
	      
	      // Método para averiguar el password por fuerza bruta
	      conseguirPassword(encriptado);
	      
	      } catch (Exception a){
		        System.err.println("Error al encriptar:" + a);  
		  }
	      
	 
	}

}
