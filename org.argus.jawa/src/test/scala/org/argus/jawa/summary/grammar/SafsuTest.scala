/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.grammar

import java.io.StringReader

import org.antlr.v4.runtime._
import org.antlr.v4.runtime.misc.ParseCancellationException
import org.scalatest.{FlatSpec, Matchers}

import scala.collection.JavaConverters._
import scala.language.implicitConversions

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SafsuTest extends FlatSpec with Matchers {
  import SafsuLexer._

  implicit def string2TestString(s: String): TestString =
    new TestString(s)

  val `:`=1
  val `;`=2
  val `~`=3
  val `=`=4
  val `+=`=5
  val `-=`=6
  val `this`=7
  val `arg`=8
  val `.`=9
  val `[]`=10
  val `@`=11
  val `classOf`=12
  val `$`=13
  val `?`=14
  val `ret`=15

  "android.content.Context:mBase:android.content.Context;" producesTokens (ID, `.`, ID, `.`, ID, `:`, ID, `:`, ID, `.`, ID, `.`, ID, `;`)
  "`Lcom/my/Class;.do:()V`" producesTokens UID
  "arg:1" producesTokens (`arg`, `:`, Digits)
  "arg:1.field.field2" producesTokens (`arg`, `:`, Digits, `.`, ID, `.`, ID)
  "arg:1[]" producesTokens (`arg`, `:`, Digits, `[]`)
  "arg:1.field.field2[]" producesTokens (`arg`, `:`, Digits, `.`, ID, `.`, ID, `[]`)
  "ret" producesTokens `ret`
  "ret.f1" producesTokens (`ret`, `.`, ID)
  "`com.my.Class.Global`" producesTokens UID
  "this.f1[]" producesTokens (`this`, `.`, ID, `[]`)
  "com.my.Class" producesTokens (ID, `.`, ID, `.`, ID)
  "com.my.Class[]@L1005" producesTokens (ID, `.`, ID, `.`, ID, `[]`, `@`, ID)
  "com.my.Class$InnerClass$InnerInnerClass@L1005" producesTokens (ID, `.`, ID, `.`, ID, `$`, ID, `$`, ID, `@`, ID)
  "arg:1=arg:2" producesTokens (`arg`, `:`, Digits, `=`, `arg`, `:`, Digits)
  "arg:1+=arg:2" producesTokens (`arg`, `:`, Digits, `+=`, `arg`, `:`, Digits)
  "arg:1-=arg:2" producesTokens (`arg`, `:`, Digits, `-=`, `arg`, `:`, Digits)
  "arg:1=com.my.Class@L1005" producesTokens (`arg`, `:`, Digits, `=`, ID, `.`, ID, `.`, ID, `@`, ID)
  "~arg:1" producesTokens (`~`, `arg`, `:`, Digits)
  "arg:1=com.my.Class@~" producesTokens (`arg`, `:`, Digits, `=`, ID, `.`, ID, `.`, ID, `@`, `~`)
  """arg:1="string"@L1""" producesTokens (`arg`, `:`, Digits, `=`, STRING, `@`, ID)
  "`Lcom/my/Class;.do:(LO1;LO2;)V`:arg:1=arg:2;" producesTokens (UID, `:`, `arg`, `:`, Digits, `=`, `arg`, `:`, Digits, `;`)
  "arg:1=com.my.Class?@L1005" producesTokens (`arg`, `:`, Digits, `=`, ID, `.`, ID, `.`, ID, `?`, `@`, ID)
  "classOf this" producesTokens (`classOf`, WS, `this`)
  """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
    |  arg:1+=arg:2
    |  ret=arg:1.field
    |  arg:2=ret
    |;
  """.stripMargin producesTokens (
    UID, `:`, WS,
    `arg`, `:`, Digits, `+=`, `arg`, `:`, Digits, WS,
    `ret`, `=`, `arg`, `:`, Digits, `.`, ID, WS,
    `arg`, `:`, Digits, `=`, `ret`, WS,
    `;`, WS)
  """/* block comment
    | */
  """.stripMargin producesTokens (COMMENT, WS)
  """/** Doc comment
    |  */
  """.stripMargin producesTokens (COMMENT, WS)
  """// line comment""" producesTokens LINE_COMMENT

  class TestString(s: String) {

    def producesTokens(tokens: Int*)() {
      check(s.stripMargin, tokens.toList)
    }

    private def check(s: String, expectedTokens: List[Int]) {
      it should ("tokenize >>>" + s + "<<< as >>>" + expectedTokens + "<<<") in {
        val reader = new StringReader(s)
        val input = CharStreams.fromReader(reader)
        val lexer = new SafsuLexer(input)
        val actualTokens: List[_ <: Token] = lexer.getAllTokens.asScala.toList
        val actualTokenTypes = actualTokens.map(_.getType)
        assert(actualTokenTypes == expectedTokens, "Tokens do not match. Expected " + expectedTokens + ", but was " + actualTokenTypes)
      }
    }

  }

  "Parser" should "not throw a parse exception on complete program" in {
    parse(
      """android.content.Context:mBase:android.content.Context;
        |
        |`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |  ret=arg:1.field
        |  arg:1.f1=arg:2.f2[]
        |  ret=arg:1.field.f3[]
        |  arg:1.f2+=arg:2
        |  ret+=arg:1.field
        |  arg:1[]-=arg:2[][]
        |  ret=arg:1.field[][].length
        |  arg:1[][]-=arg:2[]
        |  ret=arg:1.field.f3
        |  arg:1.f1=arg:2[]
        |  arg:1=`com.my.Class.Glo`.f.f2[]
        |  `com.my.Class.Glo`.f.f2[]=arg:1.field
        |  ~arg:1.f1
        |  this.f1[]=my.Class@L100
        |  ret.f1=my.Class$InnerClass?@~
        |  ret.f2="String"@L1
        |  `com.my.Class.Glo`.f2=classOf this @~
        |;
      """.stripMargin)
  }

  "Parser" should "throw a parse exception on bad program" in {
    an [ParseCancellationException] should be thrownBy {
      parse(
        """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
          |  arg:1=
          |  ret=arg:1.field
          |;
        """.stripMargin)
    }
  }

  def parse(code: String): Unit = {
    val reader = new StringReader(code)
    val input = CharStreams.fromReader(reader)
    val lexer = new SafsuLexer(input)
    val tokens = new CommonTokenStream(lexer)
    val parser = new SafsuParser(tokens)
    parser.setErrorHandler(new BailErrorStrategy)
    parser.summaryFile()
  }
}