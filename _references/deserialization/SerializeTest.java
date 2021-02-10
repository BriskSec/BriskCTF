// Ref: https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#exploitdev
// Ref: https://github.com/foxglovesec/JavaUnserializeExploits
import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.io.IOException;
 
public class SerializeTest{
 
    public static void main(String args[]) throws Exception{
        //This is the object we're going to serialize.
        MyObject myObj = new MyObject();
        myObj.name = "bob";
 
        //We'll write the serialized data to a file "object.ser"
        FileOutputStream fos = new FileOutputStream("object.ser");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        os.writeObject(myObj);
        os.close();
 
        //Read the serialized data back in from the file "object.ser"
        FileInputStream fis = new FileInputStream("object.ser");
        ObjectInputStream ois = new ObjectInputStream(fis);
 
        //Read the object from the data stream, and convert it back to a String
        MyObject objectFromDisk = (MyObject)ois.readObject();
 
        //Print the result.
        System.out.println(objectFromDisk.name);
        ois.close();
    }
}
 
class MyObject implements Serializable{
    public String name;
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException{
        in.defaultReadObject();
        this.name = this.name+"!";
    }
}