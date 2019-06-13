package org.argus.amandroid.alir.componentSummary.main

import org.argus.amandroid.core.decompile.ConverterUtil
import org.argus.amandroid.plugin.TaintAnalysisTask
import org.argus.jawa.core.util.FileUtil
import org.argus.amandroid.plugin.TaintAnalysisApproach
import org.argus.amandroid.plugin.TaintAnalysisModules
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.argus.jawa.core.MsgLevel
import org.argus.jawa.alir.Context
 
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import java.io.File
import com.sun.corba.se.impl.orbutil.threadpool.TimeoutException
import java.io.PrintWriter
import org.argus.amandroid.alir.securityconfig.RuntimeConfig
import java.io.RandomAccessFile
 

object TaintTask {
  
  def main(args: Array[String]): Unit = {
    
 
   mainloop();
     
    
    
  }
     
 private def mainloop(){
   
    var stop=false
     var evil="";
    while(!stop){
           var fileUri=FileUtil.toUri(RuntimeConfig.executePath);
     var allAPKFiles=  FileUtil.listFiles(fileUri, ".apk", recursive = false) 
     
   if(allAPKFiles.size==0){
     
     stop=true
   }
     try{ 
      allAPKFiles foreach { apkUri =>
  
       var apkPath=Set(FileUtil.toFilePath(apkUri))
     
         evil=FileUtil.toFilePath(apkUri)
       taintAnalysis(apkPath)
       val file: java.io.File = new java.io.File(FileUtil.toFilePath(apkUri))
      file.delete();
       
    } }catch{
       case ex: Exception =>{
         
         
         val logFile = new RandomAccessFile(RuntimeConfig.logPath, "rw")
          val fileLength = logFile.length;
         logFile.seek(fileLength);
         logFile.writeBytes(evil+"--Reason: Out of memory."+"\r\n")
         logFile.close();
          
        
       }
      
    }finally{
      System.gc();
     val file: java.io.File = new java.io.File(evil)
      file.delete();
     
      if(!stop)
       mainloop();
     
    }
     
     
    }
   
 }

   private def taintAnalysis(apkFiles: Set[String]): Option[TaintAnalysisResult] = {
   
     
     
    val fileUris = apkFiles.map(FileUtil.toUri)
    val outputUri = FileUtil.toUri(apkFiles.head.substring(0, apkFiles.head.length - 4))
    val reporter = new org.argus.jawa.core.PrintReporter(MsgLevel.NO)
 
   
   
    val res = TaintAnalysisTask(TaintAnalysisModules.DATA_LEAKAGE, fileUris.map((_, outputUri)), forceDelete = true, reporter, guessPackage = false, TaintAnalysisApproach.COMPONENT_BASED).run
 
    
    res 
   
    
  }

}