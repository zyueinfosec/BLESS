/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.taintAnalysis

import org.argus.jawa.alir.cfg.ICFGNode
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait TaintDescriptor {
  def desc: String
  def typ: String
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TypeTaintDescriptor(desc: String, position: Option[SSPosition], typ: String) extends TaintDescriptor {
  override def toString: String = s"$typ: $desc ${if(position.isDefined) position.get.toString else ""}".trim
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TagTaintDescriptor(desc: String, positions: ISet[SSPosition], typ: String, tags: ISet[String]) extends TaintDescriptor {
  override def toString: String = s"$typ: $desc ${positions.mkString("|")} ${tags.mkString("|")}".trim
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class TaintNode(node: ICFGNode, pos: Option[SSPosition]) {
  override def toString: FileResourceUri = {
    s"$node ${if(pos.isDefined) "param: " + pos.get else "" }".trim
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TaintSource(node: TaintNode, descriptor: TaintDescriptor)

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TaintSink(node: TaintNode, descriptor: TaintDescriptor)

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait TaintPath {
  def getSource: TaintSource
  def getSink: TaintSink
  def getTypes: ISet[String]
  def getPath: IList[TaintNode]
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait TaintAnalysisResult {
  def getSourceNodes: ISet[TaintSource]
  def getSinkNodes: ISet[TaintSink]
  def getTaintedPaths: ISet[TaintPath]
}