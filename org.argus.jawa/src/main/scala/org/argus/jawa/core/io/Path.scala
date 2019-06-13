/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.io

import java.io.RandomAccessFile
import java.net.{URI, URL}

import scala.language.implicitConversions
import scala.util.Random.alphanumeric

/** An abstraction for filesystem paths.  The differences between
 *  Path, File, and Directory are primarily to communicate intent.
 *  Since the filesystem can change at any time, there is no way to
 *  reliably associate Files only with files and so on.  Any Path
 *  can be converted to a File or Directory (and thus gain access to
 *  the additional entity specific methods) by calling toFile or
 *  toDirectory, which has no effect on the filesystem.
 *
 *  Also available are createFile and createDirectory, which attempt
 *  to create the path in question.
 *
 *  @author  Paul Phillips
 *  @since   2.8
 *
 *  ''Note:  This library is considered experimental and should not be used unless you know what you are doing.''
 */
object Path {
  def isExtensionJarOrZip(jfile: JFile): Boolean = isExtensionJarOrZip(jfile.getName)
  def isExtensionJarOrZip(name: String): Boolean = {
    val ext = extension(name)
    ext == "jar" || ext == "zip"
  }
  def extension(name: String): String = {
    var i = name.length - 1
    while (i >= 0 && name.charAt(i) != '.')
      i -= 1

    if (i < 0) ""
    else name.substring(i + 1).toLowerCase
  }

  // not certain these won't be problematic, but looks good so far
  implicit def string2path(s: String): Path = apply(s)
  implicit def jfile2path(jfile: JFile): Path = apply(jfile)

  def onlyDirs(xs: Iterator[Path]): Iterator[Directory] = xs filter (_.isDirectory) map (_.toDirectory)
  def onlyDirs(xs: List[Path]): List[Directory] = xs filter (_.isDirectory) map (_.toDirectory)
  def onlyFiles(xs: Iterator[Path]): Iterator[File] = xs filter (_.isFile) map (_.toFile)

  def roots: List[Path] = java.io.File.listRoots().toList map Path.apply

  def apply(path: String): Path = apply(new JFile(path))
  def apply(jfile: JFile): Path = try {
    def isFile = {
      jfile.isFile
    }

    def isDirectory = {
      jfile.isDirectory
    }

    if (isFile) new File(jfile)
    else if (isDirectory) new Directory(jfile)
    else new Path(jfile)
  } catch { case _: SecurityException => new Path(jfile) }

  /** Avoiding any shell/path issues by only using alphanumerics. */
  private[io] def randomPrefix = alphanumeric take 6 mkString ""
  private[io] def fail(msg: String) = throw FileOperationException(msg)
}
import org.argus.jawa.core.io.Path._

/** The Path constructor is private so we can enforce some
 *  semantics regarding how a Path might relate to the world.
 *
 *  ''Note:  This library is considered experimental and should not be used unless you know what you are doing.''
 */
class Path private[io] (val jfile: JFile) {
  val separator: Char = java.io.File.separatorChar
  val separatorStr: String = java.io.File.separator

  // conversions
  def toFile: File = new File(jfile)
  def toDirectory: Directory = new Directory(jfile)
  def toAbsolute: Path = if (isAbsolute) this else Path(jfile.getAbsolutePath)
  def toCanonical: Path = Path(jfile.getCanonicalPath)
  def toURI: URI = jfile.toURI
  def toURL: URL = toURI.toURL

  /** If this path is absolute, returns it: otherwise, returns an absolute
   *  path made up of root / this.
   */
  def toAbsoluteWithRoot(root: Path): Path = if (isAbsolute) this else root.toAbsolute / this

  /** Creates a new Path with the specified path appended.  Assumes
   *  the type of the new component implies the type of the result.
   */
  def /(child: Path): Path = if (isEmpty) child else new Path(new JFile(jfile, child.path))
  def /(child: Directory): Directory = /(child: Path).toDirectory
  def /(child: File): File = /(child: Path).toFile

  /** If this path is a container, recursively iterate over its contents.
   *  The supplied condition is a filter which is applied to each element,
   *  with that branch of the tree being closed off if it is true.  So for
   *  example if the condition is true for some subdirectory, nothing
   *  under that directory will be in the Iterator; but otherwise each
   *  file and subdirectory underneath it will appear.
   */
  def walkFilter(cond: Path => Boolean): Iterator[Path] =
    if (isFile) toFile walkFilter cond
    else if (isDirectory) toDirectory walkFilter cond
    else Iterator.empty

  /** Equivalent to walkFilter(_ => false).
   */
  def walk: Iterator[Path] = walkFilter(_ => true)

  // identity
  def name: String = jfile.getName
  def path: String = jfile.getPath
  def normalize: Path = Path(jfile.getAbsolutePath)

  def resolve(other: Path): Path = if (other.isAbsolute || isEmpty) other else /(other)
  def relativize(other: Path): Path = {
    assert(isAbsolute == other.isAbsolute, "Paths not of same type: "+this+", "+other)

    def createRelativePath(baseSegs: List[String], otherSegs: List[String]): String = {
      (baseSegs, otherSegs) match {
        case (b :: bs, o :: os) if b == o => createRelativePath(bs, os)
        case (bs, os) => (("src/main" +separator)*bs.length)+os.mkString(separatorStr)
      }
    }

    Path(createRelativePath(segments, other.segments))
  }

  def segments: List[String] = (path split separator).toList filterNot (_.length == 0)

  /**
   * @return The path of the parent directory, or root if path is already root
   */
  def parent: Directory = path match {
    case "" | "." => Directory("src/main")
    case _        =>
      // the only solution <-- a comment which could have used elaboration
      if (segments.nonEmpty && segments.last == "src/main")
        (path / "src/main").toDirectory
      else jfile.getParent match {
        case null =>
          if (isAbsolute) toDirectory // it should be a root. BTW, don't need to worry about relative pathed root
          else Directory(".")         // a dir under pwd
        case x    =>
          Directory(x)
      }
  }
  def parents: List[Directory] = {
    val p = parent
    if (p isSame this) Nil else p :: p.parents
  }
  // if name ends with an extension (e.g. "foo.jpg") returns the extension ("jpg"), otherwise ""
  def extension: String = {
    var i = name.length - 1
    while (i >= 0 && name.charAt(i) != '.')
      i -= 1

    if (i < 0) ""
    else name.substring(i + 1)
  }
  // compares against extensions in a CASE INSENSITIVE way.
  def hasExtension(ext: String, exts: String*): Boolean = {
    val lower = extension.toLowerCase
    ext.toLowerCase == lower || exts.exists(_.toLowerCase == lower)
  }
  // returns the filename without the extension.
  def stripExtension: String = name stripSuffix ("." + extension)
  // returns the Path with the extension.
  def addExtension(ext: String): Path = Path(path + "." + ext)
  // changes the existing extension out for a new one, or adds it
  // if the current path has none.
  def changeExtension(ext: String): Path = (
    if (extension == "") addExtension(ext)
    else Path(path.stripSuffix(extension) + ext)
  )

  // conditionally execute
  def ifFile[T](f: File => T): Option[T] = if (isFile) Some(f(toFile)) else None
  def ifDirectory[T](f: Directory => T): Option[T] = if (isDirectory) Some(f(toDirectory)) else None

  // Boolean tests
  def canRead: Boolean = jfile.canRead
  def canWrite: Boolean = jfile.canWrite
  def exists: Boolean = {
    try jfile.exists() catch { case _: SecurityException => false }
  }

  def isFile: Boolean = {
    try jfile.isFile catch { case _: SecurityException => false }
  }
  def isDirectory: Boolean = {
    try jfile.isDirectory catch { case _: SecurityException => jfile.getPath == "." }
  }
  def isAbsolute: Boolean = jfile.isAbsolute
  def isEmpty: Boolean = path.length == 0

  // Information
  def lastModified: Long = jfile.lastModified()
  def length: Long = jfile.length()

  // Boolean path comparisons
  def endsWith(other: Path): Boolean = segments endsWith other.segments
  def isSame(other: Path): Boolean = toCanonical == other.toCanonical
  def isFresher(other: Path): Boolean = lastModified > other.lastModified

  // creations
  def createDirectory(force: Boolean = true, failIfExists: Boolean = false): Directory = {
    val res = if (force) jfile.mkdirs() else jfile.mkdir()
    if (!res && failIfExists && exists) fail("Directory '%s' already exists." format name)
    else if (isDirectory) toDirectory
    else new Directory(jfile)
  }
  def createFile(failIfExists: Boolean = false): File = {
    val res = jfile.createNewFile()
    if (!res && failIfExists && exists) fail("File '%s' already exists." format name)
    else if (isFile) toFile
    else new File(jfile)
  }

  // deletions
  def delete(): Boolean = jfile.delete()

  /** Deletes the path recursively. Returns false on failure.
   *  Use with caution!
   */
  def deleteRecursively(): Boolean = deleteRecursively(jfile)
  private def deleteRecursively(f: JFile): Boolean = {
    if (f.isDirectory) f.listFiles match {
      case null =>
      case xs   => xs foreach deleteRecursively
    }
    f.delete()
  }

  def truncate(): Boolean =
    isFile && {
      val raf = new RandomAccessFile(jfile, "rw")
      raf setLength 0
      raf.close()
      length == 0
    }

  override def toString: String = path
  override def equals(other: Any): Boolean = other match {
    case x: Path  => path == x.path
    case _        => false
  }
  override def hashCode(): Int = path.hashCode()
}
