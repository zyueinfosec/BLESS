/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.communication

import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.ast.{AssignmentStatement, LiteralExpression, Location}
import org.argus.jawa.core.util._

/**
 * @author Fengchi Lin
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class CommunicationSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){

  override def isStmtSource(apk: ApkGlobal, loc: Location): Boolean = {
    var flag = false
    val visitor = Visitor.build({
      case as: AssignmentStatement =>
        as.rhs match {
          case le: LiteralExpression =>
            if(le.isString){
              if(le.getString.contains("call_log") && le.getString.contains("calls")) {
                flag = true
              } else if(le.getString.contains("icc") && le.getString.contains("adn")) {
                flag =true
              } else if(le.getString.contains("com.android.contacts")) {
                flag =true
              } else if(le.getString.contains("sms/")) {
                flag = true
              }
            }
            false
          case _ =>
            false
        }
    })
    visitor(loc)
    flag
  }
}
