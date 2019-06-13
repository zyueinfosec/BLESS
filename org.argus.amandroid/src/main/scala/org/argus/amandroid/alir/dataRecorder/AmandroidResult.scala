/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.dataRecorder

import org.argus.jawa.alir.dda.InterProceduralDataDependenceInfo
import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
case class AmandroidResult(idfg: InterProceduralDataFlowGraph, ddg: InterProceduralDataDependenceInfo)
