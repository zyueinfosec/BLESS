package org.argus.amandroid.alir.securityconfig;

import java.util.ArrayList;
import java.util.List;
 

public class TaintConfig {

	 public static final String TAG_TYPE="attack_type:";
	 public static final String TAG_RESULT="attack_result:";
	 public static final String NO_SECURITY="Not sercure at all";
	 public static final String NO_SECURITY_RESULT="Suffer from replay attack, reverse engineering attack and spoofing attack";
	 
	 public static final String RELPLAYATTACK="replay attack";
	 public static final String RE_GENERATE_COMMAND="regenerate command attack";
	 public static final String SPOOFING_ATTACK="spoofing attack";
	 public static final String RE_GENERATE_RESPOSE_ATTACK="spoofing attack";
	 public static final String CONTROL_DEVICE_RESULT="We can control the device anyway";
	 public static final String INJECT_FAKE_DATA_RESULT="We may inject the fake data into smartphone";
	 
	 public static final String SECURITY="It may be secure";
	 
	 
	 public static final String[] Random_Source={
			 "Ljava/util/Random;.<init>:()V",
			 "Ljava/util/Random;.nextDouble:()D",
			 "Ljava/util/Random;.nextBoolean:()Z",
			 "Ljava/util/Random;.nextFloat:()F",
			 "Ljava/util/Random;.nextInt:()I",
			 "Ljava/util/Random;.nextLong:()J",
			 "Ljava/security/SecureRandom;.<init>:()V",
			 "Ljava/util/Random;.nextBytes:([B)V ",
			 "Ljava/util/Random;.nextInt:(I)I"
				  
		 };
	 
	 public static String[] FileInput_Source={
			 "Ljava/io/InputStream;.read:()I",
			 "Ljava/io/InputStream;.read:([B)I",
			 "Ljava/io/InputStream;.read:([BII)I",
			 "Ljava/io/FileInputStream;.read:()I",
			 "Ljava/io/FileInputStream;.read:([B)I",
			 "Ljava/io/FileInputStream;.read:([BII)I",
			 "Ljava/io/Reader;.read:()I",
			 "Ljava/io/Reader;.read:([C)I",
			"Ljava/io/Reader;.read:(Ljava/nio/CharBuffer;)I",
			"Ljava/io/Reader;.read:([CII)I"
	  		  
		 };
 
	 public static String[] FileOutPut_Sink={
			 "Ljava/io/OutputStream;.write:(Lbyte[];)V",
			 "Ljava/io/OutputStream;.write:(Lbyte[];II)V",
			 "Ljava/io/OutputStream;.write:(I)V",
			 "Ljava/io/FileOutputStream;.write:(Lbyte[];)V",
			 "Ljava/io/FileOutputStream;.write:(Lbyte[];II)V",
			 "Ljava/io/FileOutputStream;.write:(I)V",
			 "Ljava/io/Writer;.write:(Lchar[];)V",
			 "Ljava/io/Writer;.write:(Lchar[];II)V",
			 "Ljava/io/Writer;.write:(I)V",
			 "Ljava/io/Writer;.write:(Ljava/lang/String;)V",
			 "Ljava/io/Writer;.write:(Ljava/lang/String;II)V",
			 "Ljava/io/FileWriter;.<init>:(Ljava/lang/String;)V",
			 "Ljava/io/File;.<init>:(Ljava/io/File;Ljava/lang/String;)V",
			 "Ljava/io/FileWriter;.<init>:(Ljava/io/File;Z)V",
			 "Ljava/io/FileOutputStream;.write:([B)V",
			 "Ljava/io/FileWriter;.write:(Ljava/lang/String;)V",
			 "Ljava/io/BufferedWriter;.write:(Ljava/lang/String;)V",
			 "Ljava/io/RandomAccessFile;.writeChar:(I)V",
			 "Ljava/io/DataOutputStream;.writeBytes:(Ljava/lang/String;)V"
			 
	 };
	 public static String[] Database_Source={
			 "Landroid/database/Cursor;.getDouble:(I)D"  
			 ,"Landroid/database/Cursor;.getFloat:(I)F"  
			 ,"Landroid/database/Cursor;.getInt:(I)I",  
			 "Landroid/database/Cursor;.getLong:(I)J"  
			 ,"Landroid/database/Cursor;.getShort:(I)S",  
			 "Landroid/database/Cursor;.getString:(I)Ljava/lang/String;",  
			 "Landroid/database/Cursor?;.getDouble:(I)D"  
			 ,"Landroid/database/Cursor?;.getFloat:(I)F"  
			 ,"Landroid/database/Cursor?;.getInt:(I)I",  
			 "Landroid/database/Cursor?;.getLong:(I)J"  
			 ,"Landroid/database/Cursor?;.getShort:(I)S",  
			 "Landroid/database/Cursor?;.getString:(I)Ljava/lang/String;",
			  "Landroid/database/sqlite/SQLiteDatabase;.openOrCreateDatabase:(Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;"
	  };	  
public static String[] Database_Sink={
			 "Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J",
			 "Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
			 "Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
			 "Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J"};
	 
  public static String[] UserInput_Source={
		  "Landroid/widget/EditText;.getText:()Landroid/text/Editable;"
		  };
  public static String[] User_DisplaySink={
		  "Landroid/widget/EditText;.setText:()Landroid/text/Editable;"
		  };
  public static String[] SharedPreferences_Source={
		 "Landroid/content/SharedPreferences;.getFloat:(Ljava/lang/String;F)F",
		  "Landroid/content/SharedPreferences;.getLong:(Ljava/lang/String;J)J", 
		  "Landroid/content/SharedPreferences;.getBoolean:(Ljava/lang/String;Z)Z",
		  "Landroid/content/SharedPreferences;.getInt:(Ljava/lang/String;I)I",
		  "Landroid/content/SharedPreferences;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
		  "Landroid/content/SharedPreferences?;.getFloat:(Ljava/lang/String;F)F",
		  "Landroid/content/SharedPreferences?;.getLong:(Ljava/lang/String;J)J", 
		  "Landroid/content/SharedPreferences?;.getBoolean:(Ljava/lang/String;Z)Z",
		  "Landroid/content/SharedPreferences?;.getInt:(Ljava/lang/String;I)I",
		  "Landroid/content/SharedPreferences?;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
  };
  
  
  public static String[] SharedPreferences_Sink={
			 "Landroid/content/SharedPreferences$Editor;.putBoolean:(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
			  "Landroid/content/SharedPreferences$Editor;.putFloat:(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;", 
			  "Landroid/content/SharedPreferences$Editor;.putInt:(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
			  "Landroid/content/SharedPreferences$Editor;.putLong:(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
			  "Landroid/content/SharedPreferences$Editor;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
			  "Landroid/content/SharedPreferences$Editor?;.putBoolean:(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
			  "Landroid/content/SharedPreferences$Editor?;.putFloat:(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;", 
			  "Landroid/content/SharedPreferences$Editor?;.putInt:(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
			  "Landroid/content/SharedPreferences$Editor?;.putLong:(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
			  "Landroid/content/SharedPreferences$Editor?;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;"
	  };
  
 
  
   public static String[] BLE_info_Source={
		   "Landroid/bluetooth/BluetoothDevice;.getAddress:()Ljava/lang/String;",
		   "Landroid/bluetooth/BluetoothDevice;.getName:()Ljava/lang/String;"
		   
   };
 
   public static String[] BLE_Serice_Source={
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.getValue:()[B",
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.getStringValue:(I)Ljava/lang/String;",
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.getIntValue:(II)I",
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.getFloatValue:(II)Ljava/lang/Float;",
		   "Landroid/bluetooth/BluetoothGattDescriptor;.getValue:()[B;"
		   
   };
   
   public static String[] BLE_Serice_Sink={
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.setValue:([B)Z",
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.setValue:(Ljava/lang/String;)Z",
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.setValue:(III)Z",
		   "Landroid/bluetooth/BluetoothGattCharacteristic;.setValue:(IIII)Z",
		   "Landroid/bluetooth/BluetoothGattDescriptor;.setValue:([B)Z"	   
   };
 
   
 
}
