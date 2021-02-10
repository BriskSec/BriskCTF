import java.io.*;

public class JavaSerial {
 
    public static void main(String args[]) throws Exception {

        VulnObj vulnObj = new VulnObj("ls");
 
        FileOutputStream fos = new FileOutputStream("/tmp/normalObj.serial");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        os.writeObject(vulnObj);
        os.flush();
        os.close();

    }

	public static String toBase64(Serializable o) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(o);
		oos.close();
		return new Base64().encodeToString(baos.toByteArray());
	}
}

class VulnObj implements Serializable {
    public String cmd;
    public VulnObj(String cmd) {
        this.cmd = cmd;
    }
}
