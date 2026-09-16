import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
/*  w  w w  . j  av  a  2  s.c  om*/
public class Main {
  public static void main(String[] args) throws Exception {
    Path existingFilePath = Paths.get("C:\\Java_Dev\\test1.txt");
    Path symLinkPath = Paths.get("C:\\test1_link.txt");
    Files.createSymbolicLink(symLinkPath, existingFilePath);
  }
}