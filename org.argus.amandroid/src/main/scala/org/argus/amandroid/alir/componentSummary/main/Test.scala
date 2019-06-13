package org.argus.amandroid.alir.componentSummary.main

import scala.concurrent.duration.FiniteDuration
import scala.concurrent.duration._
object Test {
  
  
  def main(args: Array[String]): Unit = {
    
    
    try{test()(2 seconds)}catch{
      
      case  ex:Exception =>{}
    }finally{};
  }
  
  private def test() (implicit timeout: FiniteDuration): Unit={
    var i=0;
    while(true){
    i=i+1;
    }
  
}
}

