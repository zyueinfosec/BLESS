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

import java.net.URL
import java.io._
import java.util.zip.{ZipEntry, ZipFile, ZipInputStream}
import java.util.jar.Manifest

import org.argus.jawa.core.util._

import scala.collection.mutable
import scala.annotation.tailrec

/** An abstraction for zip files and streams.  Everything is written the way
 *  it is for performance: we come through here a lot on every run.  Be careful
 *  about changing it.
 *
 *  @author  Philippe Altherr (original version)
 *  @author  Paul Phillips (this one)
 *  @version 2.0,
 *
 *  ''Note:  This library is considered experimental and should not be used unless you know what you are doing.''
 */
object ZipArchive {
  /**
   * @param   file  a File
   * @return  A ZipArchive if `file` is a readable zip file, otherwise null.
   */
  def fromFile(file: File): FileZipArchive = fromFile(file.jfile)
  def fromFile(file: JFile): FileZipArchive =
    try   { new FileZipArchive(file) }
    catch { case _: IOException => null }

  /**
   * @param   url  the url of a zip file
   * @return  A ZipArchive backed by the given url.
   */
  def fromURL(url: URL): URLZipArchive = new URLZipArchive(url)

  def fromManifestURL(url: URL): AbstractFile = new ManifestResources(url)

  private def dirName(path: String)  = splitPath(path, front = true)
  private def baseName(path: String) = splitPath(path, front = false)
  private def splitPath(path0: String, front: Boolean): String = {
    val isDir = path0.charAt(path0.length - 1) == '/'
    val path  = if (isDir) path0.substring(0, path0.length - 1) else path0
    val idx   = path.lastIndexOf('/')

    if (idx < 0)
      if (front) "/"
      else path
    else
      if (front) path.substring(0, idx + 1)
      else path.substring(idx + 1)
  }
}
import ZipArchive._
/** ''Note:  This library is considered experimental and should not be used unless you know what you are doing.'' */
abstract class ZipArchive(override val file: JFile) extends AbstractFile with Equals {
  self =>

  override def underlyingSource = Some(this)
  def isDirectory = true
  def lookupName(name: String, directory: Boolean): AbstractFile = unsupported()
  def lookupNameUnchecked(name: String, directory: Boolean): AbstractFile = unsupported()
  def create(): Unit  = unsupported()
  def delete(): Unit  = unsupported()
  def output: OutputStream = unsupported()
  def container: AbstractFile = unsupported()
  def absolute:AbstractFile = unsupported()

  /** ''Note:  This library is considered experimental and should not be used unless you know what you are doing.'' */
  sealed abstract class Entry(path: String) extends VirtualFile(baseName(path), path) {
    // have to keep this name for compat with sbt's compiler-interface
    def getArchive: ZipFile = null
    override def underlyingSource = Some(self)
    override def toString: String = self.path + "(" + path + ")"
  }

  /** ''Note:  This library is considered experimental and should not be used unless you know what you are doing.'' */
  class DirEntry(path: String) extends Entry(path) {
    val entries: MMap[String, Entry] = mmapEmpty

    override def isDirectory = true
    override def iterator: Iterator[Entry] = entries.valuesIterator
    override def lookupName(name: String, directory: Boolean): Entry = {
      if (directory) entries(name + "/")
      else entries(name)
    }
  }

  private def ensureDir(dirs: mutable.Map[String, DirEntry], path: String, zipEntry: ZipEntry): DirEntry =
    //OPT inlined from getOrElseUpdate; saves ~50K closures on test run.
    // was:
    // dirs.getOrElseUpdate(path, {
    //   val parent = ensureDir(dirs, dirName(path), null)
    //   val dir    = new DirEntry(path)
    //   parent.entries(baseName(path)) = dir
    //   dir
    // })
    dirs get path match {
      case Some(v) => v
      case None =>
        val parent = ensureDir(dirs, dirName(path), null)
        val dir    = new DirEntry(path)
        parent.entries(baseName(path)) = dir
        dirs(path) = dir
        dir
    }

  protected def getDir(dirs: mutable.Map[String, DirEntry], entry: ZipEntry): DirEntry = {
    if (entry.isDirectory) ensureDir(dirs, entry.getName, entry)
    else ensureDir(dirs, dirName(entry.getName), null)
  }
}
/** ''Note:  This library is considered experimental and should not be used unless you know what you are doing.'' */
final class FileZipArchive(file: JFile) extends ZipArchive(file) {
  lazy val (root, allDirs) = {
    val root = new DirEntry("/")
    val dirs = mutable.HashMap[String, DirEntry]("/" -> root)
    val zipFile = try {
      new ZipFile(file)
    } catch {
      case ioe: IOException => throw new IOException("Error accessing " + file.getPath, ioe)
    }

    val enum    = zipFile.entries()

    while (enum.hasMoreElements) {
      val zipEntry = enum.nextElement
      val dir = getDir(dirs, zipEntry)
      if (zipEntry.isDirectory) dir
      else {
        class FileEntry() extends Entry(zipEntry.getName) {
          override def getArchive: ZipFile = zipFile
          override def lastModified: Long = zipEntry.getTime
          override def input: InputStream = getArchive getInputStream zipEntry
          override def sizeOption   = Some(zipEntry.getSize.toInt)
        }
        val f = new FileEntry()
        dir.entries(f.name) = f
      }
    }
    (root, dirs)
  }

  def iterator: Iterator[Entry] = root.iterator

  def name: String = file.getName
  def path: String = file.getPath
  def input: InputStream = File(file).inputStream()
  def lastModified: Long = file.lastModified

  override def sizeOption = Some(file.length.toInt)
  override def canEqual(other: Any): Boolean = other.isInstanceOf[FileZipArchive]
  override def hashCode(): Int = file.hashCode
  override def equals(that: Any): Boolean = that match {
    case x: FileZipArchive => file.getAbsoluteFile == x.file.getAbsoluteFile
    case _                 => false
  }
}
/** ''Note:  This library is considered experimental and should not be used unless you know what you are doing.'' */
final class URLZipArchive(val url: URL) extends ZipArchive(null) {
  def iterator: Iterator[Entry] = {
    val root     = new DirEntry("/")
    val dirs     = mutable.HashMap[String, DirEntry]("/" -> root)
    val in       = new ZipInputStream(new ByteArrayInputStream(Streamable.bytes(input)))

    @tailrec def loop() {
      val zipEntry = in.getNextEntry
      class EmptyFileEntry() extends Entry(zipEntry.getName) {
        override def toByteArray: Array[Byte] = null
        override def sizeOption = Some(0)
      }
      class FileEntry() extends Entry(zipEntry.getName) {
        override val toByteArray: Array[Byte] = {
          val len    = zipEntry.getSize.toInt
          val arr    = if (len == 0) Array.emptyByteArray else new Array[Byte](len)
          var offset = 0

          def loop() {
            if (offset < len) {
              val read = in.read(arr, offset, len - offset)
              if (read >= 0) {
                offset += read
                loop()
              }
            }
          }
          loop()

          if (offset == arr.length) arr
          else throw new IOException("Input stream truncated: read %d of %d bytes".format(offset, len))
        }
        override def sizeOption = Some(zipEntry.getSize.toInt)
      }

      if (zipEntry != null) {
        val dir = getDir(dirs, zipEntry)
        if (zipEntry.isDirectory){}
        else {
          val f = if (zipEntry.getSize == 0) new EmptyFileEntry() else new FileEntry()
          dir.entries(f.name) = f
        }
        in.closeEntry()
        loop()
      }
    }

    loop()
    try root.iterator
    finally dirs.clear()
  }

  def name: String = url.getFile
  def path: String = url.getPath
  def input: InputStream = url.openStream()
  def lastModified: Long =
    try url.openConnection().getLastModified
    catch { case _: IOException => 0 }

  override def canEqual(other: Any): Boolean = other.isInstanceOf[URLZipArchive]
  override def hashCode(): Int = url.hashCode
  override def equals(that: Any): Boolean = that match {
    case x: URLZipArchive => url == x.url
    case _                => false
  }
}

final class ManifestResources(val url: URL) extends ZipArchive(null) {
  import collection.JavaConverters._
  def iterator: Iterator[Entry] = {
    val root     = new DirEntry("/")
    val dirs     = mutable.HashMap[String, DirEntry]("/" -> root)
    val manifest = new Manifest(input)
    val iter     = manifest.getEntries.keySet().iterator().asScala.filter(_.endsWith(".class")).map(new ZipEntry(_))

    for (zipEntry <- iter) {
      val dir = getDir(dirs, zipEntry)
      if (!zipEntry.isDirectory) {
        class FileEntry() extends Entry(zipEntry.getName) {
          override def lastModified: Long = zipEntry.getTime
          override def input: InputStream = resourceInputStream(path)
          override def sizeOption: Option[Int] = None
        }
        val f = new FileEntry()
        dir.entries(f.name) = f
      }
    }

    try root.iterator
    finally dirs.clear()
  }

  def name: String = path
  def path: String = {
    val s = url.getPath
    val n = s.lastIndexOf('!')
    s.substring(0, n)
  }
  def input: InputStream = url.openStream()
  def lastModified: Long =
    try url.openConnection().getLastModified
    catch { case _: IOException => 0 }

  override def canEqual(other: Any): Boolean = other.isInstanceOf[ManifestResources]
  override def hashCode(): Int = url.hashCode
  override def equals(that: Any): Boolean = that match {
    case x: ManifestResources => url == x.url
    case _                => false
  }

  private def resourceInputStream(path: String): InputStream = {
    new FilterInputStream(null) {
      override def read(): Int = {
        if(in == null) in = Thread.currentThread().getContextClassLoader.getResourceAsStream(path)
        if(in == null) throw new RuntimeException(path + " not found")
        super.read()
      }

      override def close(): Unit = {
        super.close()
        in = null
      }
    }
  }
}
