/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import java.io.PrintWriter

import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.dataRecorder.DataCollector
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.DataLeakageAndroidSourceAndSinkManager
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.amandroid.plugin.oauth.OAuthSourceAndSinkManager
import org.argus.amandroid.plugin.password.PasswordSourceAndSinkManager
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.Reporter
import org.argus.jawa.core.util.FileUtil
import org.argus.jawa.core.util._
import org.argus.jawa.summary.store.TaintStore
import org.argus.jawa.summary.taint.BottomUpTaintAnalysis

import scala.concurrent.duration._
import scala.language.postfixOps
import org.argus.amandroid.alir.securityconfig.TaintConfig
import org.argus.amandroid.alir.securityconfig.BleThreats
import org.argus.jawa.core.io.File
 import java.io.File
 import org.argus.amandroid.alir.securityconfig.RuntimeConfig
 import java.io.RandomAccessFile
 
 
 

object TaintAnalysisApproach extends Enumeration {
  val COMPONENT_BASED, BOTTOM_UP = Value
}

case class TaintAnalysisTask(module: TaintAnalysisModules.Value, fileUris: ISet[(FileResourceUri, FileResourceUri)], forceDelete: Boolean, reporter: Reporter, guessPackage: Boolean, approach: TaintAnalysisApproach.Value) {
  import TaintAnalysisModules._
//  private final val TITLE = "TaintAnalysisTask"
  
 
  def run: Option[TaintAnalysisResult] = {
    val yard = new ApkYard(reporter)
    val apks = fileUris.map{ case (apkUri, outputUri) =>
      val layout = DecompileLayout(outputUri)
      val strategy = DecompileStrategy(layout)
      val settings = DecompilerSettings(debugMode = false, forceDelete = forceDelete, strategy, reporter)
      yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true, guessPackage)
         
      
    }
    val ssm = module match {
      case INTENT_INJECTION =>
        new IntentInjectionSourceAndSinkManager(AndroidGlobalConfig.settings.injection_sas_file)
      case PASSWORD_TRACKING =>
        new PasswordSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
      case OAUTH_TOKEN_TRACKING =>
        new OAuthSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
      case DATA_LEAKAGE =>
        new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
      case COMMUNICATION_LEAKAGE =>
        new CommunicationSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
         
    }
    approach match {
      case TaintAnalysisApproach.BOTTOM_UP =>
        var tar: Option[TaintStore] = None
        apks.foreach { apk =>
          val ta = new BottomUpTaintAnalysis[ApkGlobal](apk, new AndroidSummaryProvider(apk), new AndroidModelCallHandler, ssm, reporter)
          val eps = apk.model.getEnvMap.map(_._2._1).toSet
          val taintMap = ta.process(eps)
          taintMap.foreach { case (_, t) =>
            tar match {
              case Some(ts) =>
                ts.merge(t)
              case None =>
                tar = Some(t)
                apk.addTaintAnalysisResult(t)
            }
          }
        }
        
        writeResult(apks)
        tar
      case TaintAnalysisApproach.COMPONENT_BASED =>
   //     ComponentBasedAnalysis.prepare(apks)(AndroidGlobalConfig.settings.timeout minutes)
         ComponentBasedAnalysis.prepare(apks)(10 minutes)
        val cba = new ComponentBasedAnalysis(yard)
        cba.phase1(apks) 
        val iddResult = cba.phase2(apks)
        val tar = cba.phase3(iddResult, ssm)
       // yard.getApk("").get.applyWhiteListPackages("")
        writeResult(apks)
        tar
    }
  }

  private def writeResult(apks: ISet[ApkGlobal]): Unit = {
    apks.foreach { apk =>
      //detecting the permission
      
       BleThreats.initalize();
       var detectflag=true;
      
        val appData = DataCollector.collect(apk)
        
      val outputDirUri = FileUtil.appendFileName(apk.model.layout.outputSrcUri, "result")
        val outputDir = FileUtil.toFile(outputDirUri)
      if (!outputDir.exists()) outputDir.mkdirs()
      val out = new PrintWriter(FileUtil.toFile(FileUtil.appendFileName(outputDirUri, "AppData.txt"))) 
        
      val res = new RandomAccessFile(RuntimeConfig.resPaht, "rw")
         
       val fileLength = res.length;
        res.seek(fileLength);
        res.writeBytes(apk.model.layout.pkg+"  ")
        out.println(apk.model.layout.pkg)
       // out.r
      if((!appData.uses_permissions.contains("android.permission.BLUETOOTH")) || !(appData.uses_permissions.contains("android.permission.BLUETOOTH_ADMIN"))){
           
          out.print("not a Bluetooth application.")
          
           out.println(BleThreats.toStringInfo())
            val fileLength = res.length;
        res.seek(fileLength);
           res.writeBytes(BleThreats.toStringInfo()+"\r\n")
          detectflag =false;
           out.close()
           res.close()
          
        } 
        
      
     
       
      if(appData.taintResultOpt==None){
        
             out.println("***********************Result***************************");
              out.println(BleThreats.toStringInfo())
            out.println("Its code may protected by tools / JNI")
          detectflag =false;
               val fileLength = res.length;
        res.seek(fileLength);
               res.writeBytes("protectbyJNI"+"\r\n")
           out.close()
           res.close()
           
          }else{
       var taintres=appData.taintResultOpt.get 
        taintres.getSinkNodes foreach{
          sinknode=>{
             var sink=sinknode.descriptor.desc.toString() 
             
             if(TaintConfig.BLE_Serice_Sink.contains(sink)){
               BleThreats.isBle=true;
               
             }
              
          }
        }
        taintres.getSourceNodes foreach{
          sourcenode=>{
             var source=sourcenode.descriptor.desc.toString() 
              
              if(TaintConfig.BLE_info_Source.contains(source)||TaintConfig.BLE_Serice_Source.contains(source)){
                BleThreats.isBle=true;
                  
              }
             
             if(source.contains("onLeScan"))
             {
               BleThreats.isBle=true;
             }
          }
        } 
       
   
          }  
        if(detectflag){
      
        
             var taintres=appData.taintResultOpt.get 
      
       
         if(taintres.getTaintedPaths.size==0){
          
            out.println("***********************Result***************************");
          out.println(TaintConfig.TAG_TYPE+TaintConfig.NO_SECURITY)
          out.println(TaintConfig.TAG_RESULT+TaintConfig.NO_SECURITY_RESULT)
          out.println(BleThreats.toStringInfo())
           val fileLength = res.length;
        res.seek(fileLength);
               res.writeBytes(BleThreats.toStringInfo()+"\r\n")
          res.close()
           out.close()
           
        }
        
      out.println("***********************************TaintPath**************************************");     
        out.println("found useful infomation blew:");
  //detecting the fuctions
       
       
        
        taintres.getTaintedPaths foreach{
          taintpath=>{
            
            
            var source=taintpath.getSource.descriptor.desc.toString()
            var sink=taintpath.getSink.descriptor.desc.toString()
             
         println(source+"----->"+sink)
         
      out.println("TaintPath:"+taintpath);
            
            
          
      
               
            
           //Case 1： if smartphone may use a key
            if(TaintConfig.Random_Source.contains(source) && TaintConfig.BLE_Serice_Sink.contains(sink)){
              //Smartphone Random and send to device
                BleThreats.smartphone_has_random=true
                println("smartphone Random and send to device");
                
            }
            
              if((TaintConfig.Random_Source.contains(source)) && (TaintConfig.Database_Sink.contains(sink)||TaintConfig.FileOutPut_Sink.contains(sink)||TaintConfig.SharedPreferences_Sink.contains(sink))){
              //save the random into database
                BleThreats.smartphone_save_random=true
                  println("smartphone save the random into disk");
           
                
              }
               
              if((TaintConfig.BLE_Serice_Source.contains(source)|| source.contains("onLeScan"))&&(TaintConfig.BLE_Serice_Sink.contains(sink))){
                
                BleThreats.device_has_random=true;
               
                  println("Device may generate a random / squence number ");
                
              }
              if((TaintConfig.BLE_Serice_Source.contains(source) || source.contains("onLeScan")) && (TaintConfig.Database_Sink.contains(sink)||TaintConfig.FileOutPut_Sink.contains(sink)||TaintConfig.SharedPreferences_Sink.contains(sink))){
                
                 BleThreats.device_has_key=true;
                
                 println("Smartphone save the data that get from device, may be a key");
                
              }
              if(TaintConfig.BLE_info_Source.contains(source) && (TaintConfig.Database_Sink.contains(sink)||TaintConfig.FileOutPut_Sink.contains(sink)||TaintConfig.SharedPreferences_Sink.contains(sink)))
                 
               {
                 BleThreats.smartphone_save_devinfo=true;
                 println("Save the name or address into disk");
               }
              
             if(TaintConfig.BLE_info_Source.contains(source)&&(TaintConfig.BLE_Serice_Sink.contains(sink))){
                
                BleThreats.smartphone_send_devinfo=true;
                  println("Smartphone send device's info to device ");
                
              }
               
              if(TaintConfig.UserInput_Source.contains(source)&& TaintConfig.BLE_Serice_Sink.contains(sink)){
                
                 BleThreats.user_write_input=true;
                  println("User input some infomation and send to device");
              }
              
              if(TaintConfig.UserInput_Source.contains(source)&& (TaintConfig.Database_Sink.contains(sink)||TaintConfig.FileOutPut_Sink.contains(sink)||TaintConfig.FileOutPut_Sink.contains(sink)||TaintConfig.SharedPreferences_Sink.contains(sink)))
                
              {
                BleThreats.user_save_input=true;
                  println("Saving userinput info");
              }
              
              if((TaintConfig.Database_Source.contains(source)||TaintConfig.FileInput_Source.contains(source)||TaintConfig.SharedPreferences_Source.contains(source))&& TaintConfig.BLE_Serice_Sink.contains(sink))
              {
                 BleThreats.key_flag=true;
                 println("it may have some kind of keys");
              }
           
              
                if(TaintConfig.BLE_Serice_Source.contains(source)&& TaintConfig.User_DisplaySink.contains(sink)){
                
                 BleThreats.key_flag=true;
                  println("display user");
              }
              
            
          }
        }
 
        out.println("***********************************Behaviours**************************************");
       out.println("found behaviour:");
        if(BleThreats.user_save_input)
       {
           out.println("save user's input into disk;");
       }
        if(BleThreats.smartphone_has_random)
        {
          out.println("smartphone can generate random number, and send to device;")
          
          
        }
        if(BleThreats.smartphone_save_devinfo){
          
          out.println("save device's info into disk;");
        }
        
        if(BleThreats.smartphone_save_random){
          
          out.println("smartphone can generate random number, and save to disk;");
        }
        if(BleThreats.smartphone_send_devinfo){
          
          out.println("smartphone use devinfo(address,name) as a part of the key;");
        }
       
       if(BleThreats.device_has_random){
          out.println("device may generate a random / squence number ");
       }
      
       if(BleThreats.user_write_input){
         
          out.println("smartphone send the user info to device ");
       }
       if(BleThreats.key_flag){
         out.println("smartphone read the data from database or a file, then send it to device");
         
       }
       if(BleThreats.device_has_key){
         
          out.println("Smartphone save the data that get from device, may be a key");
       }
       
          out.println("*********************** Attak Type & Reslut ***************************");
          
           
          if(BleThreats.smartphone_save_random &&(BleThreats.key_flag || BleThreats.smartphone_has_random))
          {
            BleThreats.smartphone_has_key=true;
            out.println("Found key: Smartphone key");
          }
          if(BleThreats.user_save_input && (BleThreats.key_flag || BleThreats.user_write_input)){
            BleThreats.user_has_key=true;
            out.println("Found key: Userinput key");
          }
          
          if(BleThreats.device_has_key){
            
             out.println("Found key: Device key");
          }
          
          if(BleThreats.smartphone_save_devinfo){
            
            if(BleThreats.smartphone_send_devinfo){
             
              out.println("It may also use device info as a part of the key");
            }else{
              
              out.println("It use devinfo as a device index");
            }
            
          }
         
    
      if(!(BleThreats.device_has_key||BleThreats.user_has_key||BleThreats.smartphone_has_key)){
        
        if(!(BleThreats.device_has_random||BleThreats.smartphone_has_random)){
          //MPOW Qradio 
            
          out.println(TaintConfig.TAG_TYPE+TaintConfig.NO_SECURITY)
          out.println(TaintConfig.TAG_RESULT+TaintConfig.NO_SECURITY_RESULT)
         
          
        }else if(BleThreats.device_has_random && !BleThreats.smartphone_has_random){
           //May use spoofing to trick the smartphone
           //Balance / Ihealthy
          
          out.println(TaintConfig.TAG_TYPE+TaintConfig.SPOOFING_ATTACK)
          out.println(TaintConfig.TAG_RESULT+TaintConfig.INJECT_FAKE_DATA_RESULT)
          out.println(TaintConfig.TAG_TYPE+TaintConfig.RE_GENERATE_COMMAND)
          out.println(TaintConfig.TAG_RESULT+TaintConfig.CONTROL_DEVICE_RESULT)
          
          
        }else if(BleThreats.smartphone_has_random &&  !BleThreats.device_has_random){
          
           
          out.println(TaintConfig.TAG_TYPE+TaintConfig.RELPLAYATTACK)
          out.println(TaintConfig.TAG_TYPE+TaintConfig.RE_GENERATE_COMMAND);
          out.println(TaintConfig.TAG_RESULT+TaintConfig.CONTROL_DEVICE_RESULT);
 
            
        }else{
          //MITM
          
          out.println(TaintConfig.TAG_TYPE+TaintConfig.RE_GENERATE_COMMAND);
          out.println(TaintConfig.TAG_RESULT+TaintConfig.CONTROL_DEVICE_RESULT);
          
        }
        
      }else if(!(BleThreats.device_has_key||BleThreats.user_has_key) && BleThreats.smartphone_has_key){
        //only smartphone has the key
        //smartphone has the key means it must has the random, so only concern is if the device has a random
        if(!BleThreats.device_has_random){
          
           out.println(TaintConfig.TAG_TYPE+TaintConfig.RELPLAYATTACK)
           out.println(TaintConfig.TAG_RESULT+TaintConfig.CONTROL_DEVICE_RESULT);
        }else{
          
          
          out.println(TaintConfig.SECURITY)
        }
        
        
      }else if(!(BleThreats.smartphone_has_key||BleThreats.user_has_key) && BleThreats.device_has_key ){
        //only the device has the key
        //device may have a random already
       out.println(TaintConfig.SECURITY)
        
       // out.println(TaintConfig.)
        
      }else if((BleThreats.smartphone_has_key||BleThreats.user_has_key) && !(BleThreats.device_has_key)){
        
         if(!(BleThreats.device_has_random)){
           
               out.println(TaintConfig.TAG_TYPE+TaintConfig.RELPLAYATTACK)
           out.println(TaintConfig.TAG_RESULT+TaintConfig.CONTROL_DEVICE_RESULT);
          
          
        }else{
           out.println(TaintConfig.SECURITY)
          
        }
      }else{
        
         out.println(TaintConfig.SECURITY)
        
      }
        

     out.println(BleThreats.toStringInfo())
      
      out.close()
       val fileLength = res.length;
        res.seek(fileLength);
               res.writeBytes(BleThreats.toStringInfo()+"\r\n")
        res.close()
        
        } 
       
    }
  }
}