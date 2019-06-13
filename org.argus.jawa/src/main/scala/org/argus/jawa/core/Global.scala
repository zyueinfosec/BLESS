/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class Global(val projectName: String, val reporter: Reporter) extends JawaClassLoadManager
  with JawaClasspathManager {
  
  /**
   * reset the current Global
   */
  def reset(removeCode: Boolean = true): Unit = {
    this.hierarchy.reset()
    if(removeCode) {
      this.applicationClassCodes.clear()
      this.userLibraryClassCodes.clear()
    }
    this.cachedClassRepresentation.invalidateAll()
    this.classCache.invalidateAll()
    this.methodCache.invalidateAll()
  }
}
