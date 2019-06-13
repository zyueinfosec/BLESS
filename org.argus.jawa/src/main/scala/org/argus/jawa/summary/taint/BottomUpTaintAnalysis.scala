/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.taint

import hu.ssh.progressbar.console.ConsoleProgressBar
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.alir.taintAnalysis.SourceAndSinkManager
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, Reporter, Signature}
import org.argus.jawa.summary.store.TaintStore
import org.argus.jawa.summary.wu.{TaintSummary, TaintWu, WorkUnit}
import org.argus.jawa.summary.{BottomUpSummaryGenerator, SummaryManager, SummaryProvider}

class BottomUpTaintAnalysis[T <: Global](
    global: T,
    provider: SummaryProvider,
    handler: ModelCallHandler,
    ssm: SourceAndSinkManager[T],
    reporter: Reporter) {

  def process(eps: ISet[Signature]): IMap[Signature, TaintStore] = {
    val sm: SummaryManager = provider.getSummaryManager
    val results: MMap[Signature, TaintStore] = mmapEmpty
    var i = 0
    eps.foreach { ep =>
      i += 1
      reporter.println(s"Processing $i/${eps.size}: ${ep.signature}")
      val cg = SignatureBasedCallGraph(global, Set(ep), None)
      val analysis = new BottomUpSummaryGenerator[T](global, sm, handler,
        TaintSummary(_, _),
        ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
      val store = new TaintStore
      val orderedWUs: IList[WorkUnit[T]] = cg.topologicalSort(true).map { sig =>
        val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
        new TaintWu(global, method, sm, handler, ssm, store)
      }
      analysis.debug = true
      analysis.build(orderedWUs)
      results(ep) = store
    }
    results.toMap
  }
}
