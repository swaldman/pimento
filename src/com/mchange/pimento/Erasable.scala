package com.mchange.pimento

/**
 *  Erasables are NOT in general thread-safe, so should only be used in single-thread contexts
 */
object Erasable:
  final case class ByteArray( value : Array[Byte] ) extends Erasable:
    def erase() : Unit = (0 to value.length).foreach(i => value(i) = 0)
  final case class CharArray( value : Array[Char] ) extends Erasable:
    def erase() : Unit = (0 to value.length).foreach(i => value(i) = 0)
trait Erasable:
  def erase() : Unit

