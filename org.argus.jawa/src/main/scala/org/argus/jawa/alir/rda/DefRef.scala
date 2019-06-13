/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.rda

import org.argus.jawa.ast.{Assignment, CallStatement, Jump}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
abstract class Slot

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
final case class VarSlot(varName: String) extends Slot {
  override def toString: String = varName
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
trait DefRef {
  self =>

  def definitions(a: Assignment): ISet[Slot]
  def strongDefinitions(a: Assignment): ISet[Slot]
  def references(j: Jump): ISet[Slot]
  def callReferences(j: CallStatement): ISeq[ISet[Slot]]
  def callDefinitions(j: CallStatement): ISeq[ISet[Slot]]
}