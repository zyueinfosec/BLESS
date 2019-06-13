/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import org.argus.jawa.alir.Context
import org.argus.jawa.core.Signature
import org.json4s._
import org.json4s.JsonDSL._
import org.json4s.native.JsonMethods._
import org.argus.jawa.core.util.{FileResourceUri, IList}

object ContextSerializer extends CustomSerializer[Context](format => (
    {
      case jv: JValue =>
        implicit val formats = format + SignatureSerializer
        val application = (jv \ "application").extract[FileResourceUri]
        val callStack = (jv \ "callStack").extract[IList[(Signature, String)]]
        val c = new Context(application)
        c.setContext(callStack)
        c
    },
    {
      case c: Context =>
        implicit val formats = format + SignatureSerializer
        ("application" -> c.application) ~
        ("callStack" -> Extraction.decompose(c.getContext))
    }
))

object ContextKeySerializer extends CustomKeySerializer[Context](format => (
  {
    case str: String =>
      implicit val formats = format + ContextSerializer
      val jv = parse(str)
      jv match {
        case JObject(List(JField("Context", v))) => Extraction.extract[Context](v)
      }
  }, {
  case c: Context =>
    implicit val formats = format + ContextSerializer
    compact(render("Context" -> Extraction.decompose(c)))
}
))