package org.argus.amandroid.alir.securityconfig;

public class BleThreats {

	 
  
	public static boolean isBle=true;
	public static boolean smartphone_save_random=false;
	public static boolean smarthone_save_userinput=false;
	public static boolean smartphone_has_random=false;
	public static boolean device_has_random=false;
	public static boolean smartphone_has_key=false;
	//public static boolean 
	public static boolean user_write_input=false;
	public static boolean device_has_key=false;
	public static boolean user_has_key=false;
	public static boolean user_save_input=false;
	public static boolean key_flag=false;
	public static boolean smartphone_save_devinfo=false;
	public static boolean smartphone_send_devinfo=false;
	
	public static void initalize(){
		  isBle=false;
		  smartphone_save_random=false;
		  smarthone_save_userinput=false;
		  smartphone_has_random=false;
		  device_has_random=false;
		  smartphone_has_key=false;
		  user_write_input=false;
		  device_has_key=false;
		  user_has_key=false;
		  user_save_input=false;
		  key_flag=false;
		  smartphone_save_devinfo=false;
		  smartphone_send_devinfo=false;
	}

 
	public static String toStringInfo() {
		return "BleThreats [isBle=" + isBle + ",smartphone_save_random="+smartphone_save_random+
				",smarthone_save_userinput="+smarthone_save_userinput+",smartphone_has_random="+smartphone_has_random+
				",device_has_random="+device_has_random+",smartphone_has_key="+smartphone_has_key+",user_write_input="+user_write_input+
				",device_has_key="+device_has_key+",user_has_key="+user_has_key+",user_save_input="+user_save_input+",key_flag="+key_flag+
				",smartphone_save_devinfo="+smartphone_save_devinfo+",smartphone_send_devinfo="+smartphone_send_devinfo+"]";
	}
	
	 
	
	
}
