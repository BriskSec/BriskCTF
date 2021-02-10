import java.io.*;
public class JavaDeserial{
 
    public static void main(String args[]) throws Exception{

        FileInputStream fis = new FileInputStream("/tmp/normalObj.serial");
        ObjectInputStream ois = new ObjectInputStream(fis);
 
        NormalObj unserObj = (NormalObj)ois.readObject();
        ois.close();
    }

    public static Object fromBase64(String s) throws IOException, ClassNotFoundException {
		byte[] data = new Base64().decode(s);
		ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
		Object o = ois.readObject();
		ois.close();
		return o;
	}
}

class NormalObj implements Serializable{
    public String name;
    public NormalObj(String name){
    this.name = name;
    }
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException{
        in.defaultReadObject();
        System.out.println(this.name);
    }
}

class VulnObj implements Serializable{
    public String cmd;
    public VulnObj(String cmd){
    this.cmd = cmd;
    }
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException{
        in.defaultReadObject();
    String s = null;
        Process p = Runtime.getRuntime().exec(this.cmd);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        while ((s = stdInput.readLine()) != null) {
            System.out.println(s);
        }
    }
}
