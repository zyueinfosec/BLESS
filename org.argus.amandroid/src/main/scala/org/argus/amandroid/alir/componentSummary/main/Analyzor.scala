package org.argus.amandroid.alir.componentSummary.main

import java.io.PrintWriter
import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.dataRecorder.DataCollector
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysis
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.DecompileLayout
import org.argus.amandroid.core.decompile.DecompileStrategy
import org.argus.amandroid.core.decompile.DecompilerSettings
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.cfg.ICFGNode
import org.argus.jawa.alir.cfg.InterProceduralControlFlowGraph
import org.argus.jawa.alir.dda.InterProceduralDataDependenceAnalysis
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.core.ClassLoadManager
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.util.FileUtil
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis
import org.argus.jawa.alir.taintAnalysis.SSPosition
import org.argus.amandroid.plugin.password.PasswordSourceAndSinkManager
import org.argus.amandroid.alir.taintAnalysis.DataLeakageAndroidSourceAndSinkManager
import org.argus.amandroid.plugin.TaintAnalysisTask
import org.argus.amandroid.plugin.TaintAnalysisModules
import org.argus.amandroid.plugin.TaintAnalysisTask

object Analyzor {
  
   
def main(args: Array[String]): Unit = {
 val inputPath="C:\\Users\\Yue\\Downloads\\BLE-amaroid\\BluetoothLe_demo.apk";
     val outputPath="C:\\Users\\Yue\\Downloads\\BLE-amaroid\\playground-test";
     /*   AndroidReachingFactsAnalysisConfig.resolve_icc = true
      AndroidReachingFactsAnalysisConfig.resolve_static_init = true
      AndroidReachingFactsAnalysisConfig.parallel = true*/
  val fileUri = FileUtil.toUri(inputPath)
    val outputUri = FileUtil.toUri(outputPath)
    val reporter = new DefaultReporter
    // Yard is the apks manager
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)

    // apk is the apk meta data manager, class loader and class manager
    val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)

  
    
/*srcs foreach {
  src =>
    val fileUri = FileUtil.toUri(FileUtil.toFilePath(outUri) + File.separator + src)
    if(FileUtil.toFile(fileUri).exists()) {
      //store the app's jawa code in AmandroidCodeSource which is organized class by class.
      apk.load(fileUri, Constants.JAWA_FILE_EXT, AndroidLibraryAPISummary)
    }
}
AppInfoCollector.collectInfo(apk, global, outUri)*/
    
    val component = apk.model.getComponents.head // get any component you want to perform analysis
    
    apk.model.getEnvMap.get(component) match {
      case Some((esig, _)) =>
        val ep = apk.getMethod(esig).get
        val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
        val icfg = new InterProceduralControlFlowGraph[ICFGNode]
        val ptaresult = new PTAResult
        val sp = new AndroidSummaryProvider(apk)
        val analysis = new AndroidReachingFactsAnalysis(
          apk, icfg, ptaresult, new AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
          AndroidReachingFactsAnalysisConfig.resolve_static_init,
          timeout = None)
        val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))
        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
        
       
        val ssm = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
        
        
        var classes= apk.getApplicationClasses
        classes foreach {
          clazz =>
            val methods=clazz.getDeclaredMethods
           methods foreach{
              method=>
                  
                if(method.getName.contains("onLeScan"))
                {
                  
                 // method.get
                  
                  println(method.toString())
                 println(method.getSignature.toString())
                 println(method.getSubSignature.toString())
                  // ssm.addSource(method.getSignature,  Set(new SSPosition("3.I[B")), Set("Test"))
                  
                   
                } 
            } 
        
        }
        
     /*   var css= ssm.getSinkSigs
        css foreach{
          c=>
            println(c.toString())
        }*/
       val taint_analysis_result = AndroidDataDependentTaintAnalysis(yard, iddResult, idfg.ptaresult, ssm)
     // val res = TaintAnalysisTask(TaintAnalysisModules.DATA_LEAKAGE, fileUri, true,reporter, true).run
       //(module: TaintAnalysisModules.Value, fileUris: ISet[(FileResourceUri, FileResourceUri)], forceDelete: Boolean, reporter: Reporter, guessPackage: Boolean, approach: TaintAnalysisApproach.Value) 
       
        
        
        
       //only can access the classes that application holds by itself
        /* ComponentBasedAnalysis.prepare(apk)(AndroidGlobalConfig.settings.timeout minutes)
        val cba = new ComponentBasedAnalysis(yard)
        cba.phase1(apk)
        val iddResult = cba.phase2(apks)*/
        //val tar = cba.phase3(iddResult, ssm)
       // val classes=apk.getApplicationClasses
        
     
  
/* var classes= apk.getApplicationClasses
        classes foreach {
          clazz =>
            val methods=clazz.getDeclaredMethods
           methods foreach{
              method=>
                 
                
                if(method.getName.contains("onLeScan"))
                {
                  
                  print(method.getName.toString())
                  
                  val cfg = JawaAlirInfoProvider.getCfg(method)
                  val rda = JawaAlirInfoProvider.getRda(method, cfg)
                  var edges=cfg.edges
                   edges foreach {
                    edge=>
                     print(edge.source.toString())
                      print("=>")
                      print(edge.target.toString())
                       println()
                 // }
                }
                   
                 
            } 
           
        }  */
        
        
      val appData = DataCollector.collect(apk)
      val outputDirUri = FileUtil.appendFileName(apk.model.layout.outputSrcUri, "result")
      val outputDir = FileUtil.toFile(outputDirUri)
      if (!outputDir.exists()) outputDir.mkdirs()
      val out = new PrintWriter(FileUtil.toFile(FileUtil.appendFileName(outputDirUri, "AppData.txt")))
       out.println("permissions:");
        
        var apppermissions=appData.uses_permissions
        apppermissions foreach{
          p=>
             out.println(p.toString());
        }
          out.println("found leakages:"+taint_analysis_result.getTaintedPaths.size)
        
      out.println("sources:")
      var sources= taint_analysis_result.getSinkNodes
        sources foreach{
          sr=>
             out.println(sr.descriptor.toString());
        }
      
       out.println("sinks:")
         var sinks=taint_analysis_result.getSinkNodes
        sinks foreach{
          sk=>
             out.println(sk.descriptor.toString());
        }  
         out.println("Paths:")
         var paths=taint_analysis_result.getTaintedPaths
        paths foreach{
          path=>
             out.println(path.toString());
        }  
      out.close() 
      case None =>
   
        yard.reporter.error("TaintAnalysis", "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest file.")
  
  }
  }
}