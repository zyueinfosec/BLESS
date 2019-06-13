/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.util

import org.argus.amandroid.core.parser.ManifestParser
import org.argus.jawa.core.JawaPackage
import org.argus.jawa.core.util._

object GuessAppPackages {

  lazy private val commonPrefix: ISet[String] = Set(
    "cn", "com", "org", "github", "java", "javax", "net", "android", "google", "edu",
    "int", "gov", "mil", "ru", "arpa")
  /**
    * Simple heuristic to guess app packages which can be used to set the whitelist
    * @param mfp Manifest Parser
    * @return
    */
  def guess(mfp: ManifestParser): ISet[String] = {
    var res: ISet[String] = isetEmpty
    if(mfp.getPackageName.nonEmpty) {
      res += mfp.getPackageName
    }
    mfp.getComponentClasses.foreach { typ =>
      if(!res.exists(p => typ.getPackageName.startsWith(p.substring(0, p.length - 2)))) {
        def findPackage(pkg: JawaPackage): Unit = {
          pkg.parent match {
            case Some(par) =>
              if(par.getPkgNameList.forall(commonPrefix.contains)) {
                res += pkg.toPkgString(".")
              } else {
                findPackage(par)
              }
            case None =>
              res += pkg.toPkgString(".")
          }
        }
        typ.getPackage match {
          case Some(pkg) => findPackage(pkg)
          case None =>
        }
      }
    }
    res
  }
}
