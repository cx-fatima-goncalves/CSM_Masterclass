import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class Sample {
    
    public Sample(){}
    
    public static String vulnerable_sha512(final String firstPart, final String secondPart) {      
    
    String algorithm = "SHA-512";
    String result = null;

    try {        
        
        MessageDigest md = MessageDigest.getInstance(algorithm);
        
        // updated code for salt
        
        byte[] data = (firstPart + secondPart).getBytes("UTF-8");
        
        md.update(data);
        
        byte[] bytes = md.digest();
        
        //end updated code for salt
        
        result = toHexRepresentation(bytes);
    } catch (NoSuchAlgorithmException e) {
        throw new HashCreatorException(e.getMessage(), e);
    } catch (UnsupportedEncodingException e) {
        throw new HashCreatorException(e.getMessage(), e);
    }

    return result;
    }
}